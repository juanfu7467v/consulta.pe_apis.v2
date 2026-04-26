import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import axios from "axios";
import cors from "cors";
import { google } from "googleapis";

dotenv.config();

const app = express();
app.set("trust proxy", true);

// 🟢 MIDDLEWARE DE SEGURIDAD Y PARSEO
// Límite de tamaño para evitar ataques de desbordamiento en el body
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// 🟢 Configuración de CORS
// Nota: Para máxima seguridad, en producción deberías cambiar origin: "*"
// por el dominio específico de tu frontend (ej: "https://miweb.com").
const corsOptions = {
  origin: "*",
  methods: "POST,OPTIONS", // Solo permitimos POST y OPTIONS (preflight)
  allowedHeaders: ["Content-Type", "x-api-key", "x-admin-key"],
  exposedHeaders: ["x-api-key", "x-admin-key"],
  credentials: true,
};
app.use(cors(corsOptions));

// -------------------- CONTEXTO DE REQUEST --------------------
app.use((req, res, next) => {
  req.requestMeta = generateMetaData();
  req.clientIp = getClientIp(req);
  next();
});

// --- VARIABLES DE ENTORNO PARA PROVEEDORES ---
const API_URL_RENIEC = process.env.API_URL_RENIEC;
const API_URL_TELEFONIA = process.env.API_URL_TELEFONIA;
const API_URL_SUNARP = process.env.API_URL_SUNARP;
const API_URL_SUNAT = "https://dniruc.apisperu.com/api/v1/ruc/";
const TOKEN_SUNAT = process.env.TOKEN_SUNAT;
const API_URL_EMPRESAS = process.env.API_URL_EMPRESAS || "";
const API_URL_MATRIMONIOS = process.env.API_URL_MATRIMONIOS || "";
const API_URL_DNI_NOMBRES = process.env.API_URL_DNI_NOMBRES || "";
const API_URL_VENEZOLANOS = process.env.API_URL_VENEZOLANOS || "";
const API_URL_CEDULA = process.env.API_URL_CEDULA || "";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_URL || "";

// -------------------- GOOGLE SHEETS AUDITORÍA --------------------
const GOOGLE_SHEETS_CREDENTIALS = {
  type: process.env.TYPE_GOOGLE_SHET,
  project_id: process.env.PROJECT_ID_GOOGLE_SHET,
  private_key_id: process.env.PRIVATE_KEY_ID_GOOGLE_SHET,
  private_key: process.env.PRIVATE_KEY_GOOGLE_SHET?.replace(/\\n/g, "\n"),
  client_email: process.env.CLIENT_EMAIL_GOOGLE_SHET,
  client_id: process.env.CLIENT_ID_GOOGLE_SHET,
  auth_uri: process.env.AUTH_URI_GOOGLE_SHET,
  token_uri: process.env.TOKEN_URI_GOOGLE_SHET,
  auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_X509_CERT_URL_GOOGLE_SHET,
  client_x509_cert_url: process.env.CLIENT_X509_CERT_URL_GOOGLE_SHET,
  universe_domain: process.env.UNIVERSE_DOMAIN_GOOGLE_SHET,
};

const GOOGLE_SPREADSHEET_ID = process.env.ID_DE_HOJA_CALCULO_GOOGLE_SHET;
const AUDIT_TIMEZONE = process.env.AUDIT_TIMEZONE || "America/Lima";

let googleSheetsService = null;
let auditSheetNameCache = null;

const ENDPOINT_AUDIT_CONFIG = {
  "/v3/consulta/dni": {
    tipoConsulta: "RENIEC",
    getInput: (body) => body?.dni ?? "",
  },
  "/v3/consulta/telefonia-doc": {
    tipoConsulta: "Telefonía",
    getInput: (body) => body?.documento ?? "",
  },
  "/v3/consulta/telefonia-num": {
    tipoConsulta: "Telefonía",
    getInput: (body) => body?.numero ?? "",
  },
  "/v3/consulta/placa": {
    tipoConsulta: "SUNARP",
    getInput: (body) => body?.placa ?? "",
  },
  "/v3/consulta/ruc": {
    tipoConsulta: "SUNAT",
    getInput: (body) => body?.data ?? "",
  },
  "/v3/consulta/razon-social": {
    tipoConsulta: "SUNAT",
    getInput: (body) => body?.data ?? "",
  },
  "/v3/consulta/empresas": {
    tipoConsulta: "EMPRESAS",
    getInput: (body) => body?.dni ?? "",
  },
  "/v3/consulta/matrimonios": {
    tipoConsulta: "MATRIMONIOS",
    getInput: (body) => body?.dni ?? "",
  },
  "/v3/consulta/buscar-dni": {
    tipoConsulta: "RENIEC_NOMBRES",
    getInput: (body) =>
      [body?.nombres, body?.apepaterno, body?.apematerno].filter(Boolean).join(" "),
  },
  "/v3/consulta/buscar-cedula": {
    tipoConsulta: "CEDULA_NOMBRES",
    getInput: (body) => body?.query ?? "",
  },
  "/v3/consulta/cedula": {
    tipoConsulta: "CEDULA",
    getInput: (body) => body?.cedula ?? "",
  },
};

const isGoogleSheetsAuditEnabled = () => {
  const required = [
    GOOGLE_SHEETS_CREDENTIALS.type,
    GOOGLE_SHEETS_CREDENTIALS.project_id,
    GOOGLE_SHEETS_CREDENTIALS.private_key_id,
    GOOGLE_SHEETS_CREDENTIALS.private_key,
    GOOGLE_SHEETS_CREDENTIALS.client_email,
    GOOGLE_SHEETS_CREDENTIALS.client_id,
    GOOGLE_SHEETS_CREDENTIALS.auth_uri,
    GOOGLE_SHEETS_CREDENTIALS.token_uri,
    GOOGLE_SHEETS_CREDENTIALS.auth_provider_x509_cert_url,
    GOOGLE_SHEETS_CREDENTIALS.client_x509_cert_url,
    GOOGLE_SHEETS_CREDENTIALS.universe_domain,
    GOOGLE_SPREADSHEET_ID,
  ];

  return required.every((value) => typeof value === "string" && value.trim() !== "");
};

const getGoogleSheetsService = async () => {
  if (!isGoogleSheetsAuditEnabled()) {
    return null;
  }

  if (googleSheetsService) {
    return googleSheetsService;
  }

  const auth = new google.auth.JWT({
    email: GOOGLE_SHEETS_CREDENTIALS.client_email,
    key: GOOGLE_SHEETS_CREDENTIALS.private_key,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });

  await auth.authorize();

  googleSheetsService = google.sheets({
    version: "v4",
    auth,
  });

  return googleSheetsService;
};

const getAuditSheetName = async () => {
  if (auditSheetNameCache) {
    return auditSheetNameCache;
  }

  const sheets = await getGoogleSheetsService();
  if (!sheets) return null;

  const spreadsheetInfo = await sheets.spreadsheets.get({
    spreadsheetId: GOOGLE_SPREADSHEET_ID,
  });

  const firstSheetTitle =
    spreadsheetInfo?.data?.sheets?.[0]?.properties?.title || "Sheet1";

  auditSheetNameCache = firstSheetTitle;
  return auditSheetNameCache;
};

const formatAuditTimestamp = (date) => {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: AUDIT_TIMEZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  const parts = formatter.formatToParts(date);
  const map = {};

  for (const part of parts) {
    if (part.type !== "literal") {
      map[part.type] = part.value;
    }
  }

  return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}:${map.second}`;
};

const getClientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  const realIp =
    req.headers["cf-connecting-ip"] ||
    req.headers["x-real-ip"] ||
    (Array.isArray(forwarded) ? forwarded[0] : forwarded?.split(",")[0]) ||
    req.socket?.remoteAddress ||
    req.ip ||
    "unknown";

  return String(realIp).replace(/^::ffff:/, "").trim();
};

const containsNoResultsText = (text) => {
  if (!text || typeof text !== "string") return false;

  const normalized = text.toLowerCase();

  const patterns = [
    "no se encontraron",
    "no se encontró",
    "sin resultados",
    "sin coincidencias",
    "no existe",
    "no encontrado",
    "no encontrada",
    "no registrado",
    "no registrada",
    "not found",
    "no data",
    "sin data",
    "resultado: 0",
    "0 resultados",
  ];

  return patterns.some((pattern) => normalized.includes(pattern));
};

const isEmptyObject = (obj) => {
  return obj && typeof obj === "object" && !Array.isArray(obj) && Object.keys(obj).length === 0;
};

const determineAuditStatus = (httpStatus, data) => {
  if (httpStatus >= 400) {
    return "ERROR";
  }

  if (data == null) {
    return "NO_RESULTS";
  }

  if (Array.isArray(data)) {
    return data.length > 0 ? "SUCCESS" : "NO_RESULTS";
  }

  if (typeof data === "string") {
    return containsNoResultsText(data) ? "NO_RESULTS" : "SUCCESS";
  }

  if (typeof data === "object") {
    const possibleText = [
      data.message,
      data.mensaje,
      data.error,
      data.detail,
      data.details,
    ]
      .filter(Boolean)
      .join(" ");

    if (containsNoResultsText(possibleText)) {
      return "NO_RESULTS";
    }

    if (data.success === false || data.status === "error" || data.status === "ERROR") {
      return "ERROR";
    }

    if (Array.isArray(data.resultados)) {
      return data.resultados.length > 0 ? "SUCCESS" : "NO_RESULTS";
    }

    if (Array.isArray(data.data)) {
      return data.data.length > 0 ? "SUCCESS" : "NO_RESULTS";
    }

    if (isEmptyObject(data)) {
      return "NO_RESULTS";
    }

    return "SUCCESS";
  }

  return "SUCCESS";
};

const getAuditInfoFromRequest = (req) => {
  const config = ENDPOINT_AUDIT_CONFIG[req.path];

  if (!config) {
    return {
      tipoConsulta: req.path,
      inputConsultado: "",
    };
  }

  return {
    tipoConsulta: config.tipoConsulta,
    inputConsultado: String(config.getInput(req.body) ?? ""),
  };
};

const appendAuditLogToGoogleSheets = async (auditPayload) => {
  try {
    const sheets = await getGoogleSheetsService();
    if (!sheets) return;

    const sheetName = await getAuditSheetName();
    if (!sheetName) return;

    const row = [
      auditPayload.timestamp,
      auditPayload.idUsuario,
      auditPayload.tipoConsulta,
      auditPayload.inputConsultado,
      auditPayload.ipOrigen,
      auditPayload.statusRespuesta,
      auditPayload.requestId,
    ];

    await sheets.spreadsheets.values.append({
      spreadsheetId: GOOGLE_SPREADSHEET_ID,
      range: `${sheetName}!A:G`,
      valueInputOption: "RAW",
      insertDataOption: "INSERT_ROWS",
      requestBody: {
        values: [row],
      },
    });
  } catch (error) {
    console.error("Error al escribir auditoría en Google Sheets:", error.message);
  }
};

const registrarAuditoriaAsync = (req, statusRespuesta) => {
  try {
    const { tipoConsulta, inputConsultado } = getAuditInfoFromRequest(req);

    const auditPayload = {
      timestamp: formatAuditTimestamp(new Date()),
      idUsuario: req.user?.id || "unknown",
      tipoConsulta,
      inputConsultado,
      ipOrigen: req.clientIp || getClientIp(req),
      statusRespuesta,
      requestId: req.requestMeta?.request_id || `req_${Date.now()}`,
    };

    setImmediate(() => {
      appendAuditLogToGoogleSheets(auditPayload).catch((error) => {
        console.error("Error asíncrono de auditoría:", error.message);
      });
    });
  } catch (error) {
    console.error("Error preparando auditoría:", error.message);
  }
};

// -------------------- FIREBASE --------------------
const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

// -------------------- FUNCIONES DE LIMPIEZA DE RESPUESTAS --------------------

/**
 * Función mejorada para limpiar y transformar respuestas de APIs de DNI y Cédula
 * Ahora procesa TODOS los resultados sin eliminar ninguno
 * Convierte el texto plano en un array JSON estructurado
 */
const limpiarRespuestaEspecial = (data) => {
  if (!data || typeof data !== "object") return data;

  // Si no tiene el campo "message" o "status", retornar sin procesar
  if (!data.message || data.status !== "success") {
    return data;
  }

  let mensaje = data.message;

  // 🔹 PASO 1: Eliminar información innecesaria del final
  // Eliminar todo desde "↞" hasta el final (incluyendo Credits, Wanted for, etc.)
  const indiceLimpieza = mensaje.indexOf("↞");
  if (indiceLimpieza !== -1) {
    mensaje = mensaje.substring(0, indiceLimpieza).trim();
  }

  // 🔹 PASO 2: Extraer el texto completo de resultados
  const resultadosCompletos = mensaje;

  // 🔹 PASO 3: Dividir por bloques de cada persona usando el patrón "DNI :"
  const bloques = resultadosCompletos
    .split(/(?=DNI\s*:\s*\d+\s*-\s*\d+)/g)
    .filter((bloque) => bloque.trim().length > 0);

  // 🔹 PASO 4: Procesar cada bloque individualmente
  const resultados = [];

  for (const bloque of bloques) {
    const persona = parsearBloquePersona(bloque);
    if (persona && Object.keys(persona).length > 0) {
      resultados.push(persona);
    }
  }

  // 🔹 PASO 5: Si no se encontraron bloques con el patrón, intentar parsear todo el mensaje
  if (resultados.length === 0) {
    const personaUnica = parsearBloquePersona(mensaje);
    if (personaUnica && Object.keys(personaUnica).length > 0) {
      return { resultados: [personaUnica] };
    }
    return data;
  }

  // 🔹 PASO 6: Retornar todos los resultados encontrados
  return {
    resultados: resultados,
    total_encontrado: resultados.length,
    mensaje_original: `Se encontraron ${resultados.length} resultados`,
  };
};

/**
 * Parsea un bloque de texto de una persona y lo convierte en un objeto JSON limpio
 * Ahora extrae TODOS los campos disponibles sin perder información
 * Y elimina específicamente los campos 'credits' y 'wanted_for'
 */
const parsearBloquePersona = (texto) => {
  if (!texto || typeof texto !== "string") return null;

  const lineas = texto
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && l.length > 0);

  const persona = {};

  const mapeoClaves = {
    dni: "dni",
    cedula: "dni",
    apellidos: "apellidos",
    nombres: "nombres",
    nombre: "nombres",
    edad: "edad",
    fecha_nacimiento: "fecha_nacimiento",
    genero: "genero",
    sexo: "genero",
    estado_civil: "estado_civil",
    direccion: "direccion",
    telefono: "telefono",
    profesion: "profesion",
    centro: "centro",
    institucion: "institucion",
    colegio: "centro",
  };

  for (const linea of lineas) {
    const match = linea.match(/^([A-ZÁÉÍÓÚÑa-záéíóúñ\s]+)\s*:\s*(.+)$/);
    if (match) {
      let clave = match[1].trim().toLowerCase();
      const valor = match[2].trim();

      clave = clave.replace(/\s*-\s*\d+$/, "").trim();

      const claveLower = clave.toLowerCase();
      if (claveLower.includes("credits") || claveLower.includes("wanted")) {
        continue;
      }

      clave = clave
        .replace(/\s+/g, "_")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "");

      const claveNormalizada = mapeoClaves[clave] || clave;

      if (!persona[claveNormalizada]) {
        persona[claveNormalizada] = valor;
      }
    }
  }

  return Object.keys(persona).length > 0 ? persona : null;
};

/**
 * Función para formatear la búsqueda de nombres según las reglas especificadas
 * Convierte "juan perez lopez" en "juan|perez|lopez"
 * Convierte "juan manuel perez lopez" en "juan,manuel|perez|lopez"
 * Convierte "juan del sol lopez" en "juan|del+sol|lopez"
 */
const formatearBusquedaNombres = (query) => {
  if (!query || typeof query !== "string") return query;

  const palabras = query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((p) => p.length > 0);

  if (palabras.length === 0) return query;

  if (palabras.length === 1) {
    return `${palabras[0]}||`;
  }

  if (palabras.length === 2) {
    return `${palabras[0]}|${palabras[1]}|`;
  }

  let nombres = [];
  let apellidoPaterno = "";
  let apellidoMaterno = "";

  const preposiciones = ["del", "de", "la", "las", "los", "san", "santa"];

  let indiceApellidoPaterno = palabras.length - 2;
  let indiceApellidoMaterno = palabras.length - 1;

  if (
    indiceApellidoPaterno > 0 &&
    preposiciones.includes(palabras[indiceApellidoPaterno - 1])
  ) {
    apellidoPaterno = palabras
      .slice(indiceApellidoPaterno - 1, indiceApellidoPaterno + 1)
      .join("+");
    nombres = palabras.slice(0, indiceApellidoPaterno - 1);
  } else {
    apellidoPaterno = palabras[indiceApellidoPaterno];
    nombres = palabras.slice(0, indiceApellidoPaterno);
  }

  apellidoMaterno = palabras[indiceApellidoMaterno];

  const nombresFormateados = nombres.join(",");

  return `${nombresFormateados}|${apellidoPaterno}|${apellidoMaterno}`;
};

// -------------------- MIDDLEWARE DE AUTENTICACIÓN --------------------
const authMiddleware = async (req, res, next) => {
  if (req.method === "OPTIONS") {
    return next();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Método no permitido. Solo se acepta POST.",
    });
  }

  const token = req.headers["x-api-key"];
  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Falta el token de API (x-api-key)",
    });
  }

  try {
    const usersRef = db.collection("usuarios");
    const snapshot = await usersRef.where("apiKey", "==", token).get();

    if (snapshot.empty) {
      return res.status(403).json({
        success: false,
        error: "Token inválido",
      });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();
    const userId = userDoc.id;

    const validPlans = ["creditos", "ilimitado"];

    if (!validPlans.includes(userData.tipoPlan)) {
      return res.status(403).json({
        success: false,
        error: "Tu plan no es válido o está deshabilitado. Recarga o contacta a soporte.",
      });
    }

    if (userData.tipoPlan === "creditos") {
      if ((userData.creditos ?? 0) <= 0) {
        return res.status(402).json({
          success: false,
          error: "No te quedan créditos, recarga tu plan para seguir consultando",
        });
      }
    }

    if (userData.tipoPlan === "ilimitado") {
      const fechaActivacion = userData.fechaActivacion
        ? userData.fechaActivacion.toDate()
        : null;
      const duracion = userData.duracionDias || 0;

      if (fechaActivacion && duracion > 0) {
        const fechaFin = new Date(fechaActivacion);
        fechaFin.setDate(fechaFin.getDate() + duracion);

        const hoy = new Date();
        if (hoy > fechaFin) {
          return res.status(403).json({
            success: false,
            error: "Sorpresa, tu plan ilimitado ha vencido, renueva tu plan para seguir consultando",
          });
        }
      } else {
        return res.status(403).json({
          success: false,
          error: "Tu plan ilimitado no es válido, por favor contacta soporte",
        });
      }
    }

    req.user = { id: userId, ...userData };
    next();
  } catch (error) {
    console.error("Error en middleware:", error);
    res.status(500).json({
      success: false,
      error: "Error interno al validar el token",
    });
  }
};

const creditosMiddleware = (costo) => {
  return async (req, res, next) => {
    if (req.method === "OPTIONS") return next();

    const domain = req.headers.origin || req.headers.referer || "Unknown/Direct Access";

    if (req.user.tipoPlan === "creditos") {
      const currentCredits = req.user.creditos ?? 0;

      if (currentCredits < costo) {
        return res.status(402).json({
          success: false,
          error: `Créditos insuficientes (Se requerían ${costo} créditos). Saldo actual: ${currentCredits}`,
        });
      }
    }

    req.logData = {
      domain: domain,
      cost: req.user.tipoPlan === "creditos" ? costo : 0,
      endpoint: req.path,
    };

    next();
  };
};

// -------------------- FUNCIONES DE APOYO --------------------
const generateMetaData = () => {
  return {
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    request_id: `req_${Math.random().toString(36).substring(2, 15)}`,
    server: "cluster-aws-pe-secure-01",
  };
};

const generateUserPlanData = (user) => {
  return {
    tipo: user.tipoPlan,
    creditosRestantes: user.tipoPlan === "creditos" ? user.creditos ?? 0 : null,
  };
};

const deducirCreditosFirebase = async (req, costo) => {
  const userRef = db.collection("usuarios").doc(req.user.id);
  const currentTime = new Date();
  const domain = req.logData.domain;

  if (req.user.tipoPlan === "creditos" && costo > 0) {
    try {
      await db.runTransaction(async (t) => {
        const freshUserDoc = await t.get(userRef);
        const currentCredits = freshUserDoc.data().creditos ?? 0;

        if (currentCredits < costo) {
          throw new Error("Saldo insuficiente durante la deducción atómica");
        }

        t.update(userRef, {
          creditos: currentCredits - costo,
          ultimaConsulta: currentTime,
          ultimoDominio: domain,
        });

        req.user.creditos = currentCredits - costo;
      });
    } catch (e) {
      console.error("Error crítico al deducir créditos:", e.message);
    }
  } else if (req.user.tipoPlan === "ilimitado") {
    await userRef.update({
      ultimaConsulta: currentTime,
      ultimoDominio: domain,
    });
  }
};

const guardarLogExterno = async (logData) => {
  if (!LOG_GUARDADO_BASE_URL) return;

  const horaConsulta = new Date(logData.timestamp).toISOString();
  const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(
    logData.domain
  )}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(
    logData.endpoint
  )}&userId=${encodeURIComponent(logData.userId)}&costo=${logData.cost}`;

  try {
    await axios.get(url);
  } catch (e) {
    console.error("Error al guardar log en API externa:", e.message);
  }
};

const limpiarRespuestaProveedor = (data) => {
  if (!data || typeof data !== "object") return data;

  const cleaned = { ...data };

  delete cleaned["developed-by"];
  delete cleaned.credits;
  delete cleaned.bot_used;
  delete cleaned.bot;
  delete cleaned.chat_id;
  delete cleaned.watermark;
  delete cleaned.provider;

  if (cleaned.error && typeof cleaned.error === "string") {
    if (
      cleaned.error.includes("Token con falta de pago") ||
      cleaned.error.includes("token expirado") ||
      cleaned.error.includes("insufficient credits")
    ) {
      cleaned.error = "Error en la consulta, intenta nuevamente";
    }
  }

  return cleaned;
};

const formatoRespuestaEstandar = (success, data, user, metadata = null) => {
  const meta = metadata || generateMetaData();

  return {
    success,
    data: limpiarRespuestaProveedor(data),
    meta,
    "consulta-pe": {
      poweredBy: "Intermediario Consulta Pe v2",
      status: "Verified Source",
      userPlan: generateUserPlanData(user),
    },
    disclaimer:
      "Información obtenida de fuentes públicas. El uso de estos datos es responsabilidad exclusiva del cliente según Ley 29733.",
  };
};

const consumirAPIProveedor = async (
  req,
  res,
  url,
  costo,
  aplicarLimpiezaEspecial = false
) => {
  try {
    const response = await axios.get(url);

    if (response.status >= 200 && response.status < 300) {
      await deducirCreditosFirebase(req, costo);

      const logData = {
        userId: req.user.id,
        timestamp: new Date(),
        ...req.logData,
      };

      // Mantener intacta la lógica actual
      guardarLogExterno(logData);

      let dataFinal = response.data;
      if (aplicarLimpiezaEspecial) {
        dataFinal = limpiarRespuestaEspecial(response.data);
      }

      const auditStatus = determineAuditStatus(response.status, dataFinal);
      registrarAuditoriaAsync(req, auditStatus);

      return res.json(
        formatoRespuestaEstandar(true, dataFinal, req.user, req.requestMeta)
      );
    } else {
      const auditStatus = determineAuditStatus(response.status, response.data);
      registrarAuditoriaAsync(req, auditStatus);

      return res.status(response.status).json(
        formatoRespuestaEstandar(false, response.data, req.user, req.requestMeta)
      );
    }
  } catch (error) {
    console.error("Error al consumir API:", error.message);

    const httpStatus = error.response ? error.response.status : 500;
    const errorData = error.response ? error.response.data : { error: error.message };

    const auditStatus = determineAuditStatus(httpStatus, errorData);
    registrarAuditoriaAsync(req, auditStatus);

    return res.status(httpStatus).json(
      formatoRespuestaEstandar(false, errorData, req.user, req.requestMeta)
    );
  }
};

// -------------------- RUTAS SEGURAS (SOLO POST) --------------------

// 1. RENIEC (7 créditos) -> /v3/consulta/dni
app.post("/v3/consulta/dni", authMiddleware, creditosMiddleware(7), async (req, res) => {
  const { dni } = req.body;
  if (!dni) {
    registrarAuditoriaAsync(req, "ERROR");
    return res.status(400).json(
      formatoRespuestaEstandar(
        false,
        { error: "DNI requerido en el body" },
        req.user,
        req.requestMeta
      )
    );
  }
  await consumirAPIProveedor(req, res, `${API_URL_RENIEC}/reniec?dni=${dni}`, 7);
});

// 2. Telefonía por Documento (9 créditos) -> /v3/consulta/telefonia-doc
app.post(
  "/v3/consulta/telefonia-doc",
  authMiddleware,
  creditosMiddleware(9),
  async (req, res) => {
    const { documento } = req.body;
    if (!documento) {
      registrarAuditoriaAsync(req, "ERROR");
      return res.status(400).json(
        formatoRespuestaEstandar(
          false,
          { error: "Documento requerido en el body" },
          req.user,
          req.requestMeta
        )
      );
    }
    await consumirAPIProveedor(
      req,
      res,
      `${API_URL_TELEFONIA}/telefonia-doc?documento=${documento}`,
      9
    );
  }
);

// 3. Telefonía por Número de Teléfono (8 créditos) -> /v3/consulta/telefonia-num
app.post(
  "/v3/consulta/telefonia-num",
  authMiddleware,
  creditosMiddleware(8),
  async (req, res) => {
    const { numero } = req.body;
    if (!numero) {
      registrarAuditoriaAsync(req, "ERROR");
      return res.status(400).json(
        formatoRespuestaEstandar(
          false,
          { error: "Número requerido en el body" },
          req.user,
          req.requestMeta
        )
      );
    }
    await consumirAPIProveedor(
      req,
      res,
      `${API_URL_TELEFONIA}/telefonia-num?numero=${numero}`,
      8
    );
  }
);

// 4. Datos SUNARP (8 créditos) -> /v3/consulta/placa
app.post("/v3/consulta/placa", authMiddleware, creditosMiddleware(8), async (req, res) => {
  const { placa } = req.body;
  if (!placa) {
    registrarAuditoriaAsync(req, "ERROR");
    return res.status(400).json(
      formatoRespuestaEstandar(
        false,
        { error: "Placa requerida en el body" },
        req.user,
        req.requestMeta
      )
    );
  }
  await consumirAPIProveedor(req, res, `${API_URL_SUNARP}/vehiculos?placa=${placa}`, 8);
});

// 5. SUNAT por RUC (6 créditos) -> /v3/consulta/ruc
app.post("/v3/consulta/ruc", authMiddleware, creditosMiddleware(6), async (req, res) => {
  const { data } = req.body;
  if (!data) {
    registrarAuditoriaAsync(req, "ERROR");
    return res.status(400).json(
      formatoRespuestaEstandar(
        false,
        { error: "RUC requerido en el body" },
        req.user,
        req.requestMeta
      )
    );
  }

  const apiUrl = `${API_URL_SUNAT}${data}?token=${TOKEN_SUNAT}`;
  await consumirAPIProveedor(req, res, apiUrl, 6);
});

// 6. SUNAT por Razón Social (5 créditos) -> /v3/consulta/razon-social
app.post(
  "/v3/consulta/razon-social",
  authMiddleware,
  creditosMiddleware(5),
  async (req, res) => {
    const { data } = req.body;
    if (!data) {
      registrarAuditoriaAsync(req, "ERROR");
      return res.status(400).json(
        formatoRespuestaEstandar(
          false,
          { error: "Razón social requerida en el body" },
          req.user,
          req.requestMeta
        )
      );
    }

    const API_URL_SUNAT_RAZON =
      process.env.API_URL_SUNAT_RAZON ||
      "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";

    await consumirAPIProveedor(req, res, `${API_URL_SUNAT_RAZON}/sunat-razon?data=${data}`, 5);
  }
);

// 7. Empresas donde figura (4 créditos) -> /v3/consulta/empresas
app.post(
  "/v3/consulta/empresas",
  authMiddleware,
  creditosMiddleware(4),
  async (req, res) => {
    const { dni } = req.body;
    if (!dni) {
      registrarAuditoriaAsync(req, "ERROR");
      return res.status(400).json(
        formatoRespuestaEstandar(
          false,
          { error: "DNI requerido en el body" },
          req.user,
          req.requestMeta
        )
      );
    }
    await consumirAPIProveedor(req, res, `${API_URL_EMPRESAS}/empresas?dni=${dni}`, 4);
  }
);

// 8. Matrimonios Registrados (6 créditos) -> /v3/consulta/matrimonios
app.post(
  "/v3/consulta/matrimonios",
  authMiddleware,
  creditosMiddleware(6),
  async (req, res) => {
    const { dni } = req.body;
    if (!dni) {
      registrarAuditoriaAsync(req, "ERROR");
      return res.status(400).json(
        formatoRespuestaEstandar(
          false,
          { error: "DNI requerido en el body" },
          req.user,
          req.requestMeta
        )
      );
    }
    await consumirAPIProveedor(req, res, `${API_URL_MATRIMONIOS}/matrimonios?dni=${dni}`, 6);
  }
);

// 9. BUSCAR DNI POR NOMBRES (5 créditos) -> /v3/consulta/buscar-dni
app.post(
  "/v3/consulta/buscar-dni",
  authMiddleware,
  creditosMiddleware(5),
  async (req, res) => {
    const { nombres, apepaterno, apematerno } = req.body;
    if (!nombres || !apepaterno || !apematerno) {
      registrarAuditoriaAsync(req, "ERROR");
      return res.status(400).json(
        formatoRespuestaEstandar(
          false,
          { error: "Nombres y apellidos requeridos en el body" },
          req.user,
          req.requestMeta
        )
      );
    }

    await consumirAPIProveedor(
      req,
      res,
      `${API_URL_DNI_NOMBRES}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`,
      5,
      true
    );
  }
);

// 10. BUSCAR CÉDULA POR NOMBRES (5 créditos) -> /v3/consulta/buscar-cedula
app.post(
  "/v3/consulta/buscar-cedula",
  authMiddleware,
  creditosMiddleware(5),
  async (req, res) => {
    const { query } = req.body;
    if (!query) {
      registrarAuditoriaAsync(req, "ERROR");
      return res.status(400).json(
        formatoRespuestaEstandar(
          false,
          { error: "Query requerido en el body" },
          req.user,
          req.requestMeta
        )
      );
    }

    const queryFormateado = formatearBusquedaNombres(query);

    await consumirAPIProveedor(
      req,
      res,
      `${API_URL_VENEZOLANOS}/venezolanos_nombres?query=${encodeURIComponent(queryFormateado)}`,
      5,
      true
    );
  }
);

// 11. CONSULTAR CÉDULA (5 créditos) -> /v3/consulta/cedula
app.post("/v3/consulta/cedula", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { cedula } = req.body;
  if (!cedula) {
    registrarAuditoriaAsync(req, "ERROR");
    return res.status(400).json(
      formatoRespuestaEstandar(
        false,
        { error: "Cédula requerida en el body" },
        req.user,
        req.requestMeta
      )
    );
  }
  await consumirAPIProveedor(req, res, `${API_URL_CEDULA}/cedula?cedula=${cedula}`, 5, true);
});

// -------------------- ENDPOINT RAIZ (HEALTH CHECK) --------------------
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "🚀 API Consulta PE Segura v3.0.0 funcionando",
    meta: req.requestMeta || generateMetaData(),
    security: {
      mode: "Strict POST",
      encryption: "TLS/SSL Enforced via Edge",
    },
  });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Servidor Seguro corriendo en http://0.0.0.0:${PORT}`);

  if (isGoogleSheetsAuditEnabled()) {
    console.log("✅ Auditoría con Google Sheets habilitada");
  } else {
    console.warn("⚠️ Auditoría con Google Sheets deshabilitada por falta de secrets");
  }
});
