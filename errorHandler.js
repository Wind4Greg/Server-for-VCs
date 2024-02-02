import { logger } from './logging.js';

export function errorHandler(err, req, res, next) {
    logger.error("Error handler received a call", err);
    let errorType = err.type;
    if (!errorType) {
        res.status(500).json({ error: err });
        return;
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
        case "deriveError":
            res.status(400).json({ errors: [err.message] });
            return;
        default:
            res.status(500).json({ errors: ["Unknown"] });
            return;
    }
}