const express = require("express");
const controller = require("../controller/oauth-controller");
const {
    allowCors,
    validateRegistration,
    validateAuthorizationRequest,
    validateTokenRequest,
} = require("../middleware/oauth-middleware");

const router = express.Router();

router.get("/.well-known/oauth-authorization-server", allowCors, controller.metadata);
router.get("/.well-known/openid-configuration", allowCors, controller.metadata);
router.get("/jwks", allowCors, controller.jwks);
router.options(["/register", "/token"], allowCors);
router.post("/register", allowCors, validateRegistration, controller.register);
router.get("/authorize", validateAuthorizationRequest, controller.showAuthorize);
router.post("/authorize", validateAuthorizationRequest, controller.approveAuthorize);
router.post("/token", allowCors, validateTokenRequest, controller.token);

module.exports = router;
