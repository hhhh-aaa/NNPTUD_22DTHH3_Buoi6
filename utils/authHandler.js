const fs = require('fs');
const path = require('path');
let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')

// Load public key for RS256 verification
const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.pem'))

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let token = req.headers.authorization.split(" ")[1];
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })

            // jwt.verify already checks exp, but we keep this guard just in case
            if (result.exp * 1000 < Date.now()) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(404).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(404).send({
                message: "ban chua dang nhap"
            })
        }

    }
}