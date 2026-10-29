const express = require("express");
const config = require("./helper/config");
const oauthRouter = require("./routes/oauth-route");

const app = express();

app.set("trust proxy", true);
app.disable("x-powered-by");
app.use(express.json({limit: "32kb"}));
app.use(express.urlencoded({extended: false, limit: "32kb"}));
app.use(oauthRouter);

app.get("/", (req, res) => res.json({status: "ok", issuer: config.issuer}));

app.listen(config.port, () => {
    console.log(`MCP OAuth server listening on port ${config.port}`);
    console.log(`Metadata URL: ${config.issuer}/.well-known/oauth-authorization-server`);
});
