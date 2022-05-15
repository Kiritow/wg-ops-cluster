const crypto = require('crypto')
const { BaseDaoClass } = require('./base-dao')

class NodeDao extends BaseDaoClass {
    async createNode(nodeUUID, hostname, ip, fingerprintSha1) {
        let conn = null
        try {
            conn = await this.getConnection()
            const res = await conn.query(`insert into node set ?`, [{
                uuid: nodeUUID,
                hostname,
                ip,
                status: 1,
            }])
            const nodeId = res.insertId
            await conn.query(`insert into clientcert set ?`, [{
                node_id: nodeId,
                sha1: fingerprintSha1,
            }])
            await conn.commit()

            return nodeId
        } catch (e) {
            console.log(e)

            if (conn) conn.close()

            return -1
        }
    }

    async verifyCert(nodeUUID, fingerprintSha1) {
        return (await this.query('select count(1) as n from clientcert where status=1 and sha1=? and node_id in (select id from node where status=1 and uuid=?)', [fingerprintSha1, nodeUUID]))[0].n > 0
    }
}

module.exports = NodeDao
