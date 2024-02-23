import { logger } from './logging.js';

export function errorHandler(err, req, res, next) {
    let errorType = err.type;
    if (!errorType) {
        logger.error("Error handler received an unknown type (500 return)", err);
        res.status(500).json({ error: err });
        return;
    } else {
        logger.error("Error handler received a known type", err);
    }
    errorType = errorType.trim();
    switch (errorType) {
        case "entity.too.large":
            res.status(400).json({ errors: [`JSON input limit of ${err.limit} exceeded`] });
            return;
        case "invalidCredential":
            res.status(400).json({ errors: [err.errors[0].message] });
            return;
        case "invalidProof":
            res.status(400).json({ errors: ["proof: " + err.errors[0].message] });
            return;
        case "missingDocument":
            res.status(400).json({ errors: ["no credential supplied"] });
            return;
        case "missingProof":
            res.status(400).json({ errors: ["no proof on credential"] });
            return;
        case "nothingSelected":
            res.status(400).json({ errors: ["Nothing selected"] });
            return;
        case "verifyError":
        case "verifyBaseError":
        case "deriveError":
            res.status(400).json({ errors: [err.message] });
            return;
        default:
            res.status(500).json({ errors: ["Unknown"] });
            return;
    }
}