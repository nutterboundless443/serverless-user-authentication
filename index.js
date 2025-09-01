const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const db = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = process.env.USERS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

exports.handler = async (event) => {
    // 处理不同的HTTP方法
    switch (event.httpMethod) {
        case 'POST':
            return await handlePost(event);
        default:
            return { statusCode: 405, body: '不支持的方法' };
    }
};

async function handlePost(event) {
    const body = JSON.parse(event.body);
    switch (body.action) {
        case 'register':
            return await registerUser(body);
        case 'login':
            return await loginUser(body);
        default:
            return { statusCode: 400, body: '无效的操作' };
    }
}

async function registerUser(body) {
    const { username, password } = body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const params = {
        TableName: USERS_TABLE,
        Item: { username, password: hashedPassword }
    };
    await db.put(params).promise();
    return { statusCode: 200, body: JSON.stringify({ message: '用户注册成功' }) };
}

async function loginUser(body) {
    const { username, password } = body;
    const params = {
        TableName: USERS_TABLE,
        Key: { username }
    };
    const user = await db.get(params).promise();
    if (!user.Item) {
        return { statusCode: 401, body: JSON.stringify({ message: '用户名未找到' }) };
    }
    const passwordMatch = await bcrypt.compare(password, user.Item.password);
    if (!passwordMatch) {
        return { statusCode: 401, body: JSON.stringify({ message: '密码错误' }) };
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    return { statusCode: 200, body: JSON.stringify({ token }) };
}