const bodyParser = require('body-parser');
var cors = require('cors')
const express = require('express');
const morgan = require('morgan');
const mongoose = require('mongoose');
require('dotenv/config')
const app = express();
const env = process.env
const apiUrl = env.API_URL

app.use(bodyParser.json());
app.use(morgan('tiny'));
app.use(cors());
app.options('*', cors());

// register routes
const authRouter = require('./routes/auth')
app.use(`/${apiUrl}/`, authRouter)

const port = env.PORT;
const hostName = env.HOST

mongoose.connect(env.MONGODB_CONNECTION_STRING).then(() => {
    console.log('Connected ot db')
}).catch((error) => console.log(error))

app.listen(port, hostName, () => {
    console.log(`App listening in port: ${port}`)
})