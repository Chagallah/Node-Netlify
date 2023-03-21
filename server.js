const express = require("express");
const dotenv = require("dotenv");
const logger = require("morgan");
const cors = require("cors");
require("colors");
const corsOpts = {
    origin: '*',

    methods: [
        'GET',
        'POST',
    ],

    allowedHeaders: [
        'Content-Type',
    ],
};

app.use(cors(corsOpts));

const db = require("./config/db");
const swaggerUi = require('swagger-ui-express'),
    swaggerDocument = require('./swagger.json');

const app = express();

dotenv.config({ path: "./config/config.env" });

if (process.env.NODE_ENV === "production") console.log = function () { };

if (process.env.NODE_ENV === "development") app.use(logger("dev"));

// app.use(cors());

// DB Connection
db(app);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use("/api/v1/user", require("./routes/user"));
app.use("/api/v1/food", require("./routes/food"));
// app.use("/api/v1/admin", require("./routes/admin"));

module.exports = app;
