const koa = require('koa')
const koaRouter = require('koa-router')
const koaJson = require('koa-json')
const koaBodyparser = require('koa-bodyparser')
const crypto = require('crypto')
const fs = require('fs')
const { spawn } = require('child_process')
const { promisify } = require('util')

const PathCAKey = process.env.PATH_CA_KEY || '/data/ca-key.pem'
const PathCACert = process.env.PATH_CA_CERT || '/data/ca-cert.pem'
const PathServerKey = process.env.PATH_SERVER_KEY || '/data/server-key.pem'
const PathServerCert = process.env.PATH_SERVER_CERT || '/data/server-cert.pem'

const nodeDao = new (require('./node-dao'))({
    host: 'db',
    port: 3306,
    user: 'root',
    password: 'default_password',
    database: 'wgops_cluster_api',
})

function runCommandCheckCode(cmdPath, args) {
    return new Promise((resolve, reject) => {
        const child = spawn(cmdPath, args)
        child.on('close', (code) => code == 0 ? resolve(code) : reject(code))
        child.stdout.on('data', (data) => console.log(data.toString()))
        child.stderr.on('data', (data) => console.log(data.toString()))
    })
}

async function initCA() {
    if (!fs.existsSync(PathCAKey)) {
        console.log(`create new CA key: ${PathCAKey}`)
        await runCommandCheckCode('openssl', ['genrsa', '-out', PathCAKey, '4096'])
    } else {
        console.log(`using CA key: ${PathCAKey}`)
    }

    if (!fs.existsSync(PathCACert)) {
        console.log(`create new CA cert: ${PathCACert}`)
        await runCommandCheckCode('openssl', ['req', '-new', '-x509', '-subj', '/CN=selfsigned-app-ca', '-nodes', '-days', '3650', '-key', PathCAKey, '-out', PathCACert])
    } else {
        console.log(`using CA cert: ${PathCACert}`)
    }
}

async function initServer() {
    if (!fs.existsSync(PathServerKey)) {
        console.log(`create new server key: ${PathServerKey}`)
        await runCommandCheckCode('openssl', ['genrsa', '-out', PathServerKey, '4096'])
    } else {
        console.log(`using server key: ${PathServerKey}`)
    }

    if (!fs.existsSync(PathServerCert)) {
        console.log(`creating server cert: ${PathServerCert}`)
        await runCommandCheckCode('openssl', ['req', '-new', '-sha256', '-subj', `/CN=cluster-api-server-selfsigned`, '-key', PathServerKey, '-out', `/tmp/server.csr`])
        await runCommandCheckCode('openssl', ['x509', '-req', '-days', 365, '-in', `/tmp/server.csr`, '-out', PathServerCert, '-CAcreateserial', '-CA', PathCACert, '-CAkey', PathCAKey])
        fs.unlinkSync('/tmp/server.csr')
    } else {
        console.log(`using server cert: ${PathServerCert}`)
    }
}

async function issueClientCert(clientId, commonName) {
    console.log(`issue client cert: CN=${commonName} id=${clientId}`)

    await runCommandCheckCode('openssl', ['genrsa', '-out', `/tmp/${clientId}-key.pem`, '4096'])
    await runCommandCheckCode('openssl', ['req', '-new', '-sha256', '-subj', `/CN=${commonName}`, '-key', `/tmp/${clientId}-key.pem`, '-out', `/tmp/${clientId}.csr`])
    await runCommandCheckCode('openssl', ['x509', '-req', '-days', 365, '-in', `/tmp/${clientId}.csr`, '-out', `/tmp/${clientId}-cert.pem`, '-CAcreateserial', '-CA', PathCACert, '-CAkey', PathCAKey])
    const cert = await promisify(fs.readFile)(`/tmp/${clientId}-cert.pem`, 'utf-8')
    const key = await promisify(fs.readFile)(`/tmp/${clientId}-key.pem`, 'utf-8')
    await Promise.all(new Array(`/tmp/${clientId}.csr`, `/tmp/${clientId}-key.pem`, `/tmp/${clientId}-cert.pem`).map((filename) => promisify(fs.unlink)(filename)))
    return { cert, key }
}

const app = new koa()
app.use(koaBodyparser())
app.use(koaJson())

const router = new koaRouter()
router.post('/join', async (ctx) => {
    const nodeUUID = crypto.randomUUID()

    try {
        const { cert, key } = await issueClientCert(nodeUUID, nodeUUID)
        const certSha1 = new crypto.X509Certificate(Buffer.from(cert, 'utf-8')).fingerprint.replace(':', '').toLowerCase()
        const nodeId = await nodeDao.createNode(nodeUUID, ctx.query.name, ctx.headers['x-forwarded-for'], certSha1)
        if (nodeId < 0) {
            ctx.status = 200
            ctx.body = {
                code: 1,
                message: 'unable to create node',
            }
            return
        }

        ctx.status = 200
        ctx.body = { 
            code: 0,
            message: 'success',
            data: { cert, key, nodeId }
        }
    } catch (e) {
        console.log(e)

        ctx.status = 500
        ctx.body = "Server Internal Error"
    }
})

async function EnsureCert(ctx) {
    if (ctx.headers['ssl-client-verify'] != 'SUCCESS') {
        ctx.status = 401
        return null
    }

    const fingerprint = ctx.headers['ssl-client-fingerprint']
    const uuid = ctx.headers['ssl-client-sdn'].split('=')[1]

    if (!nodeDao.verifyCert(uuid, fingerprint)) {
        ctx.status = 401
        return null
    }

    return uuid
}

router.get('/info', async (ctx) => {
    console.log(ctx.request.headers)
    if (!await EnsureCert(ctx)) return

    ctx.status = 200
    ctx.body = Object.keys(ctx.request.headers).filter(k => k.startsWith('ssl-')).reduce((obj, k) => { obj[k] = ctx.request.headers[k]; return obj }, {})
})

app.use(router.routes()).use(router.allowedMethods())

initCA().then(initServer).then(()=>{
    app.listen(3000)
})

Object.entries({
    SIGHUP: 1,
    SIGINT: 2,
    SIGTERM: 14
}).forEach(([name, code]) => {
    process.on(name, ()=>{
        console.log(`app received ${name}, exit gracefully...`)
        process.exit(code)
    })
})
