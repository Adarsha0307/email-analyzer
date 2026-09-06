import express from 'express';
import { analyzeEmail, analyzePassword, analyzeUrl } from '../services/analyzers.js';

const router = express.Router();

function requireText(value, name, maxLength) {
  if (typeof value !== 'string' || !value.trim()) {
    const error = new Error(`${name} is required.`);
    error.status = 400;
    throw error;
  }
  if (value.length > maxLength) {
    const error = new Error(`${name} must not exceed ${maxLength} characters.`);
    error.status = 413;
    throw error;
  }
  return value;
}

router.post('/url', async (req, res, next) => {
  try {
    const url = requireText(req.body?.url, 'URL', 4096);
    return res.json(await analyzeUrl(url));
  } catch (error) {
    return next(error);
  }
});

router.post('/email', async (req, res, next) => {
  try {
    const text = requireText(req.body?.text, 'Email content', 100000);
    return res.json(await analyzeEmail(text));
  } catch (error) {
    return next(error);
  }
});

router.post('/password', async (req, res, next) => {
  try {
    const password = requireText(req.body?.password, 'Password', 1024);
    return res.json(analyzePassword(password));
  } catch (error) {
    return next(error);
  }
});

export default router;
