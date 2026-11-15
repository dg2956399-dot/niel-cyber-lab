
module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      erro: "Método não permitido."
    });
  }

  try {
    const { dominio } = req.body || {};

    if (
      typeof dominio !== "string" ||
      dominio.length > 253 ||
      !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(dominio)
    ) {
      return res.status(400).json({
        erro: "Informe um domínio válido, sem protocolo ou caminho."
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
        erro: "O domínio redirecionou a consulta. Verifique o endereço informado."
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

    const encontrados = Object.values(verificacoes)
      .filter(Boolean).length;

    return res.status(200).json({
      dominio,
      statusHTTP: resposta.status,
      verificacoes,
      encontrados,
      total: Object.keys(verificacoes).length,
      aviso: "Verificação básica dos cabeçalhos recebidos. A ausência de um cabeçalho não confirma, sozinha, uma vulnerabilidade."
    });

  } catch (erro) {
    return res.status(502).json({
      erro: "Não foi possível consultar o domínio. Verifique o endereço e tente novamente."
    });
  }
};
