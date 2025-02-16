const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const winston = require("winston");
const { body, validationResult } = require('express-validator');
const path = require('path');
const fs = require('fs');
require("dotenv").config();

// Criar diretório de logs se não existir
const logDir = './logs';
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

// Configuração do Logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    }),
    new winston.transports.File({ 
      filename: path.join(logDir, 'error.log'),
      level: 'error'
    }),
    new winston.transports.File({ 
      filename: path.join(logDir, 'combined.log')
    })
  ]
});

const app = express();

// Middlewares de Segurança
app.use(helmet());
app.use(mongoSanitize());
app.use(express.json({ limit: '10kb' }));

// Configuração do CORS
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.CORS_ORIGIN 
    : 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX
});
app.use('/noticias', limiter);

// Modelo de Notícia
const NoticiaSchema = new mongoose.Schema({
  titulo: String,
  conteudo: String,
  categoria: String,
  data: { type: Date, default: Date.now }
});
const Noticia = mongoose.model("Noticia", NoticiaSchema);

// Middleware de Logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// Rotas
app.get("/noticias", async (req, res) => {
  const noticias = await Noticia.find();
  res.json(noticias);
});

app.get("/noticias/:id", async (req, res) => {
  const noticia = await Noticia.findById(req.params.id);
  if (!noticia) return res.status(404).json({ erro: "Notícia não encontrada" });
  res.json(noticia);
});

const validarNoticia = [
  body('titulo')
    .notEmpty()
    .trim()
    .isLength({ min: 5, max: 100 })
    .withMessage('O título deve ter entre 5 e 100 caracteres'),
  body('conteudo')
    .notEmpty()
    .isLength({ min: 20 })
    .withMessage('O conteúdo deve ter no mínimo 20 caracteres'),
  body('categoria')
    .notEmpty()
    .isIn(['política', 'economia', 'tecnologia', 'esportes', 'entretenimento'])
    .withMessage('Categoria inválida')
];

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

app.post("/noticias", validarNoticia, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { titulo, conteudo, categoria } = req.body;
  const noticia = new Noticia({ titulo, conteudo, categoria });
  await noticia.save();
  res.status(201).json(noticia);
});

app.put("/noticias/:id", async (req, res) => {
  const noticia = await Noticia.findByIdAndUpdate(req.params.id, req.body, { new: true });
  if (!noticia) return res.status(404).json({ erro: "Notícia não encontrada" });
  res.json(noticia);
});

app.delete("/noticias/:id", async (req, res) => {
  const noticia = await Noticia.findByIdAndDelete(req.params.id);
  if (!noticia) return res.status(404).json({ erro: "Notícia não encontrada" });
  res.json({ mensagem: "Notícia removida com sucesso" });
});

// Rota de teste/health check
app.get('/', (req, res) => {
  res.json({ 
    message: 'API de Notícias está funcionando!',
    timestamp: new Date(),
    status: 'online'
  });
});

// Middleware de erro global melhorado
app.use((err, req, res, next) => {
  logger.error(err.stack);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      erro: 'Erro de validação',
      detalhes: err.message
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      erro: 'ID inválido',
      detalhes: 'O formato do ID fornecido é inválido'
    });
  }

  res.status(500).json({ 
    erro: 'Erro interno do servidor',
    mensagem: process.env.NODE_ENV === 'development' ? err.message : 'Algo deu errado'
  });
});

const PORT = process.env.PORT || 3000;

const connectWithRetry = async () => {
  try {
    logger.info("Tentando conectar ao MongoDB...");
    
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      retryWrites: true
    });
    
    logger.info("MongoDB conectado com sucesso");
  } catch (err) {
    logger.error("Erro ao conectar ao MongoDB:", err.message);
    process.exit(1);  // Encerra o processo se não conseguir conectar
  }
};

const startServer = async () => {
  try {
    logger.info("Iniciando servidor...");
    logger.info(`Porta configurada: ${PORT}`);
    
    await connectWithRetry();

    const server = app.listen(PORT, '0.0.0.0', () => {
      logger.info(`Servidor rodando na porta ${PORT}`);
      logger.info(`Ambiente: ${process.env.NODE_ENV}`);
    });

    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Porta ${PORT} já está em uso`);
        process.exit(1);
      } else {
        logger.error("Erro no servidor:", error);
        process.exit(1);
      }
    });

  } catch (error) {
    logger.error("Erro ao iniciar o servidor:", error);
    process.exit(1);
  }
};

if (!process.env.MONGO_URI) {
  logger.error('MONGO_URI não configurada');
  process.exit(1);
}

startServer();
