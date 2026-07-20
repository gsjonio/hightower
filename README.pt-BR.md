# hightower

[EN](README.md) | PT-BR

[![CI](https://github.com/gsjonio/hightower/actions/workflows/ci.yml/badge.svg)](https://github.com/gsjonio/hightower/actions/workflows/ci.yml)
[![CodeQL](https://github.com/gsjonio/hightower/actions/workflows/codeql.yml/badge.svg)](https://github.com/gsjonio/hightower/actions/workflows/codeql.yml)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange?logo=rust)](Cargo.toml)
[![Release](https://img.shields.io/github/v/release/gsjonio/hightower)](https://github.com/gsjonio/hightower/releases/latest)
[![License: MIT](https://img.shields.io/github/license/gsjonio/hightower)](LICENSE)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue?logo=github)](https://github.com/gsjonio/hightower/wiki)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_a_Coffee-gugamenezes-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/gugamenezes)

Uma ferramenta de linha de comando para Windows que lista todos os processos em
execução e explica, em linguagem simples, o que cada um é -- destacando os
desconhecidos ou fora do lugar. Feita para quem não faz ideia do que significam
todos aqueles nomes no Gerenciador de Tarefas.

> Não conhece as entranhas do Windows? Comece pelo guia para leigos
> ([docs/GUIDE.pt-BR.md](docs/GUIDE.pt-BR.md)): ele explica cada termo e cada
> coluna da tabela em linguagem simples.

## Índice

- [Recursos](#recursos)
- [Instalação](#instalação)
- [Arquitetura](#arquitetura)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Uso](#uso)
- [Heurísticas de risco e aviso](#heurísticas-de-risco-e-aviso)
- [Notas](#notas)
- [Apoie](#apoie)
- [Licença](#licença)

## Recursos

- `hightower scan --all` -- lista todos os processos com PID, caminho completo,
  categoria, publisher (quando verificável) e um veredito de risco em linguagem
  simples.
- `hightower explain <name|pid>` -- explicação em linguagem simples de um único
  processo: o que é, se ter várias cópias é normal, caminho esperado vs. real.
- `hightower scan --json` -- o mesmo scan em JSON, para scripts.
- Offline-first: sem rede, sem telemetria, nunca.

Os três comandos já funcionam, incluindo vereditos de risco, verificação de
assinatura Authenticode e o banco de processos conhecidos embarcado.

## Instalação

Somente Windows.

**Recomendado -- sem precisar de Rust.** Baixe o instalador, leia o script (boa
prática para qualquer script vindo da internet) e então execute:

```powershell
irm https://raw.githubusercontent.com/gsjonio/hightower/main/install.ps1 -OutFile install.ps1
# leia o install.ps1 e então:
.\install.ps1
```

Ele coloca o `hightower.exe` em `%LOCALAPPDATA%\Programs\hightower` e adiciona
essa pasta ao PATH do seu **usuário** -- sem direitos de administrador, sem tocar
em nada fora do seu perfil. **Abra um terminal novo** depois e rode
`hightower scan`.

Rodar de novo atualiza no lugar. Para remover: `.\uninstall.ps1`. O binário não é
assinado, então o SmartScreen pode avisar na primeira execução.

**A partir do código-fonte** -- requer o toolchain Rust (1.82+):

```sh
git clone https://github.com/gsjonio/hightower.git
cd hightower
cargo install --path cli
```

O `cargo install` coloca o binário em `%USERPROFILE%\.cargo\bin`; garanta que
essa pasta esteja no seu PATH. (O rustup normalmente adiciona -- se o `hightower`
não for encontrado num terminal novo, é por isso.)

## Arquitetura

O hightower é um workspace Cargo organizado como arquitetura hexagonal (ports &
adapters), um crate por anel:

- **`core`** -- o domínio e as ports (traits). Lógica pura, **zero dependência
  de sistema operacional**. Não depende do crate `windows`, então qualquer
  tentativa de chamar o Windows a partir do domínio *não compila* -- a fronteira
  é garantida pelo compilador, não pela revisão de código.
- **`adapters`** -- o lado dirigido: implementações reais das ports no Windows
  (listagem de processos via ToolHelp32, verificação de assinatura Authenticode)
  e o banco de processos conhecidos embarcado.
- **`cli`** -- o lado que dirige: parsing de argumentos e a raiz de composição
  que liga os adapters ao core.

Veja a [página Architecture da wiki](https://github.com/gsjonio/hightower/wiki/Architecture)
para a justificativa completa.

## Estrutura do projeto

```text
hightower/
├── core/        domínio + ports (traits). Sem deps de SO.
├── adapters/    adapters Windows (ToolHelp32, Authenticode) + banco de processos.
└── cli/         clap + raiz de composição; gera o binário `hightower`.
```

## Uso

```sh
hightower scan --all          # explica todos os processos em execução
hightower scan --json         # o mesmo, em JSON para scripts
hightower explain <name|pid>  # detalha um único processo
```

## Heurísticas de risco e aviso

O hightower é uma **ferramenta educativa, não um antivírus.** Ele usa
heurísticas simples para destacar processos que merecem um olhar humano:

1. Um processo conhecido do Windows (ex. `svchost.exe`) rodando de fora de
   `%SystemRoot%\System32` / `SysWOW64` -- técnica clássica de masquerading.
2. Um binário sem assinatura válida ou confiável.
3. Um processo rodando de `Temp`, `Downloads` ou `AppData\Roaming` sem
   assinatura.
4. Um nome ausente do banco de processos conhecidos e sem publisher reconhecido
   -- reportado como `desconhecido, revise manualmente`.

**Essas heurísticas geram falsos positivos e falsos negativos.** Um veredito
`suspicious` não significa malware, e um veredito `trusted` não garante
segurança. O hightower nunca manda você matar ou excluir um processo do sistema.
Na dúvida, pesquise o processo ou pergunte a alguém de confiança -- não aja com
base apenas no veredito.

## Notas

- Alguns processos protegidos exigem um terminal elevado (administrador) para
  detalhes completos. Sem isso aparecem como `restricted` -- nunca são
  descartados nem derrubam o scan.
- Sem acesso à rede, sem telemetria.

## Apoie

O hightower é livre e de código aberto. Se ele te poupar tempo, você pode apoiar
o desenvolvimento com um café. Obrigado!

[![Buy Me a Coffee](https://img.shields.io/badge/Buy_Me_a_Coffee-gugamenezes-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/gugamenezes)

## Licença

[MIT](LICENSE)
