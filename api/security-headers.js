
const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const ADMIN_UID = process.env.ADMIN_UID;

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      sucesso: false,
      erro: "Método não permitido."
    });
  }

  try {
    const authorization = req.headers.authorization || "";
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({
        sucesso: false,
        erro: "Sessão não autorizada."
      });
    }

    const { data, error } = await supabase.auth.getUser(token);

    if (
      error ||
      !data.user ||
      data.user.id !== ADMIN_UID
    ) {
      return res.status(403).json({
        sucesso: false,
        erro: "Acesso exclusivo do administrador."
      });
    }

    const { dominio } = req.body || {};

    if (
      typeof dominio !== "string" ||
      dominio.length > 253 ||
      !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(dominio)
    ) {
      return res.status(400).json({
        sucesso: false,
        erro: "Informe um domínio válido."
      });
    }

    const resposta = await fetch(`https://${dominio}`, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
      headers: {
        "User-Agent": "NIEL-SECURITY-OPERATIONS/4.0"
      }
    });

    if (resposta.status >= 300 && resposta.status < 400) {
      return res.status(400).json({
        sucesso: false,
        erro: "Redirecionamento bloqueado."
      });
    }

    const cabecalhos = resposta.headers;

    const verificacoes = {
      "Strict-Transport-Security": cabecalhos.has("strict-transport-security"),
      "Content-Security-Policy": cabecalhos.has("content-security-policy"),
      "X-Content-Type-Options": cabecalhos.has("x-content-type-options"),
      "X-Frame-Options": cabecalhos.has("x-frame-options"),
      "Referrer-Policy": cabecalhos.has("referrer-policy"),
      "Permissions-Policy": cabecalhos.has("permissions-policy")
    };

    const encontrados = Object.values(verificacoes).filter(Boolean).length;

    return res.status(200).json({
      sucesso: true,
      versao: "4.0",
      dominio,
      statusHTTP: resposta.status,
      verificacoes,
      encontrados,
      total: Object.keys(verificacoes).length,
      aviso: "Auditoria básica dos cabeçalhos HTTP."
    });

  } catch (erro) {
    return res.status(502).json({
      sucesso: false,
      erro: "Não foi possível concluir a auditoria."
    });
  }
};
