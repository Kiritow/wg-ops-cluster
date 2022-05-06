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
const PathClientCerts = process.env.PATH_CLIENT_CERTS || '/data'

function runCommand(cmdPath, args) {
    return new Promise((resolve, reject) => {
        const child = spawn(cmdPath, args)
        child.on('close', (code) => code == 0 ? resolve(code) : reject(code))
        child.stdout.on('data', (data) => console.log(data.toString()))
        child.stderr.on('data', (data) => console.log(data.toString()))
    })
}

async function initCA() {
    if (!fs.existsSync(PathCAKey)) await runCommand('openssl', ['genrsa', '-out', PathCAKey, '4096'])
    if (!fs.existsSync(PathCACert)) await runCommand('openssl', ['req', '-new', '-x509', '-subj', '/CN=selfsigned-app-ca', '-nodes', '-days', '3650', '-key', PathCAKey, '-out', PathCACert])
}

function initServer() {
    if (!fs.existsSync(PathServerKey)) await runCommand('openssl', ['genrsa', '-out', PathServerKey, '4096'])
    if (!fs.existsSync(PathServerCert)) {
        await runCommand('openssl', ['req', '-new', '-sha256', '-subj', `/CN=cluster-api-server-selfsigned`, '-key', PathServerKey, '-out', `/data/server.csr`])
        await runCommand('openssl', ['x509', '-req', '-days', 365, '-in', `/data/server.csr`, '-out', PathServerCert, '-CAcreateserial', '-CA', PathCACert, '-CAkey', PathCAKey])
    }
}

async function issueClientCert(clientId, commonName) {
    await runCommand('openssl', ['genrsa', '-out', `/data/${clientId}-key.pem`, '4096'])
    await runCommand('openssl', ['req', '-new', '-sha256', '-subj', `/CN=${commonName}`, '-key', `/data/${clientId}-key.pem`, '-out', `/data/${clientId}.csr`])
    await runCommand('openssl', ['x509', '-req', '-days', 365, '-in', `/data/${clientId}.csr`, '-out', `/data/${clientId}-cert.pem`, '-CAcreateserial', '-CA', PathCACert, '-CAkey', PathCAKey])
}

const app = new koa()
app.use(koaBodyparser())
app.use(koaJson())

const router = new koaRouter()
router.post('/join', async (ctx) => {
    const certLocalId = crypto.randomUUID()

    try {
        await issueClientCert(certLocalId, ctx.query.name)
    } catch (e) {
        console.log(e)
    }

    ctx.status = 200
    ctx.body = {
        cert: await promisify(fs.readFile)(`${PathClientCerts}/${certLocalId}-cert.pem`, 'utf-8'),
        key: await promisify(fs.readFile)(`${PathClientCerts}/${certLocalId}-key.pem`, 'utf-8'),
    }
})

router.get('/info', (ctx) => {
    console.log(ctx.request.headers)

    ctx.status = 200
    ctx.body = Object.keys(ctx.request.headers).filter(k => k.startsWith('ssl-')).reduce((obj, k) => { obj[k] = ctx.request.headers[k]; return obj }, {})
})

app.use(router.routes()).use(router.allowedMethods())

initCA().then(initServer).then(()=>{
    app.listen(3000)
})
