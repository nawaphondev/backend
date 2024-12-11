const nodemailer = require('nodemailer');

const sendMaintenanceReminder = (email, equipmentName, maintenanceDate) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.MAIL_USER,
        to: email,
        subject: `Maintenance Reminder for ${equipmentName}`,
        text: `Please remember to perform maintenance on ${equipmentName} scheduled for ${maintenanceDate}.`
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.log('Error sending email:', err);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
};

module.exports = sendMaintenanceReminder;
