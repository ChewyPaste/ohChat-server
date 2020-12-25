const User = require('../models').User;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/app');
const { validationResult } = require('express-validator');

exports.login = async (req, res) => {
	const { email, password } = req.body;

	try {
		//find the user

		const secret = require('crypto').randomBytes(64).toString('hex');
		const user = await User.findOne({
			where: {
				email
			}
		});
		//check if user found
		if (!user) return res.status(404).json({ message: 'user not found' });
		// console.log(bcrypt.compareSync(password, user.password));
		if (!bcrypt.compareSync(password, user.password)) {
			return res.status(401).json({ message: 'Incorrect password' });
		}
		const userWithToken = generateToken(user.get({ raw: true }));
		userWithToken.user.avatar = user.avatar;
		return res.send(userWithToken);
	} catch (e) {
		// res.send(e.message);
		return res.status(500).json({ message: e.message });
	}
};
exports.register = async (req, res) => {
	try {
		const user = await User.create({ ...req.body });
		// return res.send('okay');
		const userWithToken = generateToken(user.get({ raw: true }));

		res.status(202).json(userWithToken);
	} catch (err) {
		//validation error means violation of unique property for that column
		return res.status(500).json({ err: message });
	}
};

const generateToken = (user) => {
	delete user.password;
	const token = jwt.sign(user, config.appKey, { expiresIn: 86400 });
	return { ...{ user }, ...{ token } };
};
