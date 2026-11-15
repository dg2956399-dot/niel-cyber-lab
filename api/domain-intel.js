
module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      sucesso: false,
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

  const tiposDNS = {
    A: 1,
    AAAA: 28,
    MX: 15,
    NS: 2,
    TXT: 16,
    CAA: 257
  };

  const nomesTipos = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    257: "CAA"
  };

  try {
    const { dominio: entrada } = req.body || {};

    if (!validarDominio(entrada)) {
      return res.status(400).json({
        sucesso: false,
        erro: "Informe um domínio válido, sem protocolo ou caminho."
      });
    }

    const dominio = entrada.trim().toLowerCase();

    const consultarDNS = async (tipo) => {
      try {
        const url =
          `https://dns.google/resolve?name=${encodeURIComponent(dominio)}&type=${tiposDNS[tipo]}`;

        const resposta = await fetch(url, {
          signal: AbortSignal.timeout(10000),
          headers: {
            "Accept": "application/dns-json",
            "User-Agent": "NIEL-SECURITY-OPERATIONS/4.0"
          }
        });

        if (!resposta.ok) {
          throw new Error("Falha HTTP na consulta DNS");
        }

        const dados = await resposta.json();

        if (typeof dados.Status !== "number") {
          throw new Error("Resposta DNS inválida");
        }

        const respostas = Array.isArray(dados.Answer)
          ? dados.Answer
          : [];

        // Separa CNAME dos registros realmente solicitados.
        const aliases = respostas
          .filter((item) => item.type === 5)
          .map((item) => ({
            nome: item.name,
            tipo: "CNAME",
            valor: item.data,
            TTL: item.TTL
          }));

        // Aceita somente registros do tipo consultado.
        const registros = respostas
          .filter((item) => item.type === tiposDNS[tipo])
          .map((item) => ({
            nome: item.name,
            tipo: nomesTipos[item.type] || "DESCONHECIDO",
            valor: item.data,
            TTL: item.TTL
          }));

        let situacao;
        let mensagem;

        if (dados.Status === 3) {
          situacao = "dominio_inexistente";
          mensagem = "O DNS retornou NXDOMAIN.";
        } else if (dados.Status === 2 || dados.Status === 5) {
          situacao = "erro_dns";
          mensagem = "O servidor DNS não conseguiu concluir a consulta.";
        } else if (dados.Status !== 0) {
          situacao = "erro_dns";
          mensagem = "A consulta retornou um código DNS inesperado.";
        } else if (registros.length > 0) {
          situacao = "encontrado";
          mensagem = "Registros encontrados.";
        } else {
          situacao = "sem_registro";
          mensagem = aliases.length > 0
            ? "Foi encontrado um alias CNAME, mas nenhum registro do tipo solicitado."
            : "Nenhum registro deste tipo foi encontrado.";
        }

        return {
          tipo,
          status: dados.Status,
          situacao,
          mensagem,
          quantidade: registros.length,
          registros,
          aliases
        };

      } catch (erro) {
        return {
          tipo,
          situacao: "falha_consulta",
          mensagem: "Não foi possível consultar este tipo de registro DNS.",
          quantidade: 0,
          registros: [],
          aliases: []
        };
      }
    };

    const consultasDNS = await Promise.all(
      Object.keys(tiposDNS).map(consultarDNS)
    );

    // Consulta de certificados públicos.
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

      if (!Array.isArray(dadosCertificados)) {
        throw new Error("Resposta inválida");
      }

      const nomes = new Set();

      certificados = dadosCertificados
        .filter((certificado) => certificado.name_value)
        .slice(0, 200)
        .map((certificado) => {
          const nomesCertificado = certificado.name_value
            .split(/\r?\n/)
            .map((nome) => nome.trim().toLowerCase())
            .filter(Boolean);

          nomesCertificado.forEach((nome) => {
            const limpo = nome.replace(/^\*\./, "");

            if (
              limpo === dominio ||
              limpo.endsWith("." + dominio)
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
      versao: "4.0",
      dominio,
      dataConsulta: new Date().toISOString(),

      dns: consultasDNS,

      resumoDNS: {
        totalTiposConsultados: consultasDNS.length,
        encontrados: consultasDNS.filter(
          (item) => item.situacao === "encontrado"
        ).length,
        semRegistro: consultasDNS.filter(
          (item) => item.situacao === "sem_registro"
        ).length,
        falhas: consultasDNS.filter(
          (item) =>
            item.situacao === "falha_consulta" ||
            item.situacao === "erro_dns" ||
            item.situacao === "dominio_inexistente"
        ).length
      },

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
        "Registros DNS podem variar conforme o servidor consultado.",
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

