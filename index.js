const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const db = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = process.env.USERS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

exports.handler = async (event) => {
    // Handle different HTTP methods
    switch (event.httpMethod) {
        case 'POST':
            return await handlePost(event);
        default:
            return { statusCode: 405, body: 'Method Not Allowed' };
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
            return { statusCode: 400, body: 'Invalid operation' };
    }
}

async function registerUser(body) {
    const { username, password } = body;
    // Check if the user already exists
    const paramsCheck = {
        TableName: USERS_TABLE,
        Key: { username }
    };
    const userCheck = await db.get(paramsCheck).promise();
    if (userCheck.Item) {
        return { statusCode: 400, body: JSON.stringify({ message: 'Username already exists' }) };
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const params = {
        TableName: USERS_TABLE,
        Item: { username, password: hashedPassword }
    };
    await db.put(params).promise();
    return { statusCode: 200, body: JSON.stringify({ message: 'User registered successfully' }) };
}

async function loginUser(body) {
    const { username, password } = body;
    const params = {
        TableName: USERS_TABLE,
        Key: { username }
    };
    const user = await db.get(params).promise();
    if (!user.Item) {
        return { statusCode: 401, body: JSON.stringify({ message: 'Username not found' }) };
    }
    const passwordMatch = await bcrypt.compare(password, user.Item.password);
    if (!passwordMatch) {
        return { statusCode: 401, body: JSON.stringify({ message: 'Incorrect password' }) };
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    return { statusCode: 200, body: JSON.stringify({ token }) };
}