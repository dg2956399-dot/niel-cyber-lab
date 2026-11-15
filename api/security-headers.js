
async function analisarCabecalhosReais() {
  if (!acessoLiberado || !dominioAutorizado) {
    alert("Prepare primeiro um domínio autorizado.");
    return;
  }

  const saida = document.getElementById("resultadoScanner");
  saida.textContent = "Consultando cabeçalhos HTTP reais...";

  try {
    const resposta = await fetch("/api/security-headers", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        dominio: dominioAutorizado
      })
    });

    const dados = await resposta.json();

    if (!resposta.ok) {
      throw new Error(dados.erro || "Falha na consulta.");
    }

    let texto = "ANÁLISE HTTP REAL\n";
    texto += "Domínio: " + dados.dominio + "\n";
    texto += "Status HTTP: " + dados.statusHTTP + "\n\n";

    for (const [nome, presente] of Object.entries(dados.verificacoes)) {
      texto += (presente ? "🟢 " : "🔴 ") +
        nome + ": " +
        (presente ? "PRESENTE" : "AUSENTE") + "\n";
    }

    texto += "\nResultado: " + dados.encontrados +
      "/" + dados.total + " verificações presentes.";

    texto += "\n\n" + dados.aviso;

    saida.textContent = texto;

    await registrarEventoScanner(
      "Análise HTTP realizada: " + dados.dominio
    );

  } catch (erro) {
    saida.textContent = "ERRO NA ANÁLISE:\n" + erro.message;
  }
}
