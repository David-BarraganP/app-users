const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const { sendEmail } = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken')

const getAll = catchError(async (req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async (req, res) => {
    const { password, email, firstName, frontBaseUrl } = req.body
    const hashedPasswor = await bcrypt.hash(password, 10)

    const newBody = { ...req.body, password: hashedPasswor }
    const result = await User.create(newBody);

    const code = require('crypto').randomBytes(64).toString('hex')

    await EmailCode.create({
        code: code,
        userId: result.id
    })

    sendEmail({
        to: email,
        subject: 'Verificacion de cuenta',
        html: `
        <div style="max-width: 500px; margin: 50px auto; background-color: #F8FAFC; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif; color: #333333;">
          <h1 style="color: #007BFF; font-size: 28px; text-align: center; margin-bottom: 20px;">¡Hola ${firstName.toUpperCase()}🖐!</h1>
          <p style="font-size: 18px; line-height: 1.6; margin-bottom: 25px; text-align: center;">Gracias por registrarte en nuestra aplicación. Para verificar su cuenta, haga clic en el siguiente enlace:</p>
          <div style="text-align: center;">
              <a href="${frontBaseUrl}/verify_email/${code}" style="display: inline-block; background-color: #007BFF; color: #FFFFFF; text-align: center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">¡Verificar cuenta!</a>
          </div>
        </div>
    `
    })

    return res.status(201).json(result);
});



const getOne = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if (!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.destroy({ where: { id } });
    if (!result) return res.sendStatus(404);
    return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
    const { id } = req.params;
    const fieldsToDelete = ['email', 'password', 'isverifed']
    fieldsToDelete.forEach(field => {
        delete req.body[field]
    })

    const result = await User.update(
        req.body,
        { where: { id }, returning: true }
    );
    if (result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyUser = catchError(async (req, res) => {
    const { code } = req.params

    const userCode = await EmailCode.findOne({ where: { code } })
    if (!userCode) return res.status(401).json({ error: "Not User Found" })

    const user = await User.findByPk(userCode.userId)

    await user.update(
        { isVerifed: true }
    )
    await userCode.destroy()

    return res.json(user)

})

const login = catchError(async (req, res) => {
    const { email, password } = req.body

    const user = await User.findOne({ where: { email } })
    if (!user) res.sendStatus(401)

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) res.sendStatus(401)

    const token = jwt.sign(
        { user },
        process.env.TOKEN_SECRET,
        { expiresIn: "1 d" }
    )

    return res.json({ user, token })

})

const logged = catchError(async (req, res) => {
    const user = req.user

    return res.json(user)

})

const resetPassword = catchError(async (req, res) => {
    const { email, frontBaseUrl } = req.body

    const user = await User.findOne({ where: { email } })
    if (!user) return res.status(401).json({ error: "User not found" })

    const code = require('crypto').randomBytes(64).toString('hex')

    await EmailCode.create({
        code: code,
        userId: user.id
    })

    sendEmail({
        to: email,
        subject: 'Restablecer contraseña',
        html: `
            <div style="max-width: 500px; margin: 50px auto; background-color: #F8FAFC; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif; color: #333333;">
                <h1 style="color: #007BFF; font-size: 28px; text-align: center; margin-bottom: 20px;">Restablecer Contraseña</h1>
                <p style="font-size: 18px; line-height: 1.6; margin-bottom: 25px; text-align: center;">Hemos recibido una solicitud para restablecer la contraseña de tu cuenta. Para continuar con el proceso, haz clic en el siguiente enlace:</p>
                <div style="text-align: center;">
                    <a href="${frontBaseUrl}/reset_password/${code}" style="display: inline-block; background-color: #007BFF; color: #FFFFFF; text-align: center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">Restablecer Contraseña</a>
                </div>
            </div>
        `
    });


    return res.json(user)
});


const updatePassword = catchError(async (req, res) => {
   
    const {code} = req.params
    const {password} = req.body

    const emailCode = await EmailCode.findOne({where: {code}})

    if (!emailCode) return res.status(401).json({ error: "email not  Found" })

    const user = await User.findByPk(emailCode.userId )

    const newPassword = await bcrypt.hash(password, 10)

    const userUpdate = await user.update({
        password: newPassword
    }) 

    await emailCode.destroy()


    return res.json(emailCode)
});


module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyUser,
    login,
    logged,
    resetPassword,
    updatePassword 
}