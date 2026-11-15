
module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      erro: "Método não permitido."
    });
  }

  const validarDominio = (dominio) => {
    return (
      typeof dominio === "string" &&
      dominio.length <= 253 &&
      /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(dominio)
    );
  };

  try {
    const { dominio } = req.body || {};

    if (!validarDominio(dominio)) {
      return res.status(400).json({
        erro: "Informe um domínio válido, sem protocolo ou caminho."
      });
    }

    const tiposDNS = ["A", "AAAA", "MX", "NS", "TXT", "CAA"];

    const consultarDNS = async (tipo) => {
      try {
        const url =
          `https://dns.google/resolve?name=${encodeURIComponent(dominio)}&type=${tipo}`;

        const resposta = await fetch(url, {
          signal: AbortSignal.timeout(10000),
          headers: {
            "Accept": "application/dns-json",
            "User-Agent": "NIEL-SECURITY-OPERATIONS/4.0"
          }
        });

        if (!resposta.ok) {
          throw new Error("Falha na consulta DNS");
        }

        const dados = await resposta.json();

        return {
          tipo,
          status: dados.Status,
          registros: (dados.Answer || []).map((item) => ({
            nome: item.name,
            tipo: item.type,
            valor: item.data,
            TTL: item.TTL
          }))
        };
      } catch (erro) {
        return {
          tipo,
          erro: "Consulta DNS indisponível."
        };
      }
    };

    const consultasDNS = await Promise.all(
      tiposDNS.map(consultarDNS)
    );

    let certificados = [];
    let subdominios = [];
    let erroCertificados = null;

    try {
      const urlCertificados =
        `https://crt.sh/?q=${encodeURIComponent("%." + dominio)}&output=json`;

      const respostaCertificados = await fetch(urlCertificados, {
        signal: AbortSignal.timeout(15000),
        headers: {
          "Accept": "application/json",
          "User-Agent": "NIEL-SECURITY-OPERATIONS/4.0"
        }
      });

      if (!respostaCertificados.ok) {
        throw new Error("Consulta indisponível");
      }

      const dadosCertificados = await respostaCertificados.json();

      const nomes = new Set();

      certificados = dadosCertificados
        .filter((certificado) => {
          return certificado.name_value;
        })
        .slice(0, 200)
        .map((certificado) => {
          const nomesCertificado = certificado.name_value
            .split(/\r?\n/)
            .map((nome) => nome.trim().toLowerCase())
            .filter(Boolean);

          nomesCertificado.forEach((nome) => {
            const limpo = nome.replace(/^\*\./, "");

            if (
              limpo === dominio.toLowerCase() ||
              limpo.endsWith("." + dominio.toLowerCase())
            ) {
              if (!nome.startsWith("*.")) {
                nomes.add(nome);
              }
            }
          });

          return {
            emissor: certificado.issuer_name || null,
            nome: certificado.common_name || null,
            validadeInicio: certificado.not_before || null,
            validadeFim: certificado.not_after || null,
            nomes: nomesCertificado
          };
        });

      subdominios = [...nomes].slice(0, 300);

    } catch (erro) {
      erroCertificados =
        "Não foi possível consultar os registros públicos de certificados.";
    }

    return res.status(200).json({
      sucesso: true,
      dominio,
      dataConsulta: new Date().toISOString(),

      dns: consultasDNS,

      certificados: {
        fonte: "crt.sh",
        totalRegistros: certificados.length,
        registros: certificados
      },

      subdominios: {
        totalEncontrados: subdominios.length,
        nomes: subdominios
      },

      avisos: [
        "As informações são provenientes de fontes públicas.",
        "Subdomínios encontrados em certificados não significam que estejam ativos.",
        "A ausência de resultados não confirma a inexistência de registros.",
        "Esta consulta não realiza exploração ou invasão de sistemas."
      ],

      erroCertificados
    });

  } catch (erro) {
    return res.status(502).json({
      sucesso: false,
      erro: "Não foi possível concluir o reconhecimento do domínio."
    });
  }
};
