const { DataTypes } = require('sequelize');
const sequelize = require('../utils/connection');

const EmailCode = sequelize.define('emailCode', {
    code: {
        type: DataTypes.STRING,
        allowNull: false
    },
    // code
});

module.exports = EmailCode;