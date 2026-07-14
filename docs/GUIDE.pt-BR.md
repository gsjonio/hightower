# hightower -- Guia para Leigos

[EN](GUIDE.md) | PT-BR

Este guia é para pessoas que **não** são técnicas. Não precisa saber nada antes.
Se uma palavra parecer assustadora, a gente explica aqui em linguagem simples.

## Para que serve o hightower?

Seu computador está sempre rodando vários programinhas em segundo plano, mesmo
quando você não está fazendo nada. Alguns fazem parte do Windows. Outros são de
aplicativos que você instalou. E de vez em quando, um deles é algo que não
deveria estar ali.

O **hightower** te mostra essa lista e explica, em palavras simples, o que cada
item é -- para você perceber o que está fora do lugar.

> O hightower é um ajudante, **não um antivírus**. Ele aponta coisas que valem um
> olhar; não remove nada e nem sempre está certo. Pense nele como um amigo que
> entende bem de Windows apontando e dizendo "hm, esse aí parece estranho".

## Algumas palavras explicadas

- **Processo:** um programa em execução. Não é o ícone que você clicou -- é o
  *motor* por trás dele. Um app pode ter vários processos.
- **PID:** um número que o Windows dá a cada processo, como uma senha de
  atendimento. É diferente cada vez que o processo inicia. Você raramente
  precisa dele.
- **Caminho (path):** *onde* o programa mora no disco, ex.
  `C:\Windows\System32\svchost.exe`. Isso é uma pista importante: programas
  confiáveis do Windows moram em pastas confiáveis.
- **Assinatura digital:** um tipo de selo à prova de violação da empresa que fez
  o programa (como a Microsoft). Se o selo é válido, você sabe quem fez e que
  ninguém alterou. O hightower vai usar isso numa versão futura.

## Como rodar

O hightower é uma ferramenta de **linha de comando** -- você digita um comando em
vez de clicar. Abra um terminal (aperte Iniciar, digite "Terminal" ou
"PowerShell", tecle Enter) e então:

```sh
hightower scan --all
```

Você recebe uma tabela com todos os processos em execução. Para ver mais detalhes
dos programas protegidos do sistema, rode o terminal **como Administrador**
(clique com o botão direito -> "Executar como administrador").

## Lendo a tabela

```text
Scanned 252 running processes:

  PID  NAME                 PATH
    4  System               (restricted)
 1234  explorer.exe         C:\Windows\explorer.exe
 5678  chrome.exe           C:\Program Files\Google\Chrome\Application\chrome.exe
```

- **NAME** -- o nome do processo.
- **PATH** -- onde ele mora. `C:\Windows\...` e `C:\Program Files\...` são lares
  normais e confiáveis.
- **(restricted)** -- o Windows não deixou o hightower ler os detalhes deste. Isso
  é **completamente normal** para programas protegidos do sistema. Rode como
  Administrador para ver mais. **Não** significa que o processo é ruim.

## "Por que tem dez cópias da mesma coisa?"

Totalmente normal. O Windows roda várias cópias de alguns programas de propósito
-- o `svchost.exe` é o famoso; ter uma dúzia ao mesmo tempo é esperado. Um nome
repetido **não** é, sozinho, um sinal de alerta.

O sinal de alerta é um nome confiável no **lugar errado**. Um `svchost.exe` de
verdade mora em `C:\Windows\System32`. Um `svchost.exe` rodando da sua pasta
`Downloads` é o tipo suspeito -- é um truque que malware usa, vestindo um nome
confiável como fantasia. (O hightower vai destacar exatamente isso numa versão
futura.)

## Se algo parecer estranho -- o que fazer, e o que NÃO fazer

**NÃO** exclua nem "mate" um processo na hora só porque ele parece
desconhecido. Muitos nomes esquisitos são parte normal do Windows, e parar o
errado pode quebrar seu sistema ou fazê-lo reiniciar.

Em vez disso:

1. **Olhe o PATH.** Está em `C:\Windows\...` ou `C:\Program Files\...`? Isso é
   normal. Está em `Downloads`, `Temp` ou `AppData`? Aí merece mais atenção.
2. **Pesquise o nome exato na internet**, junto com a palavra "processo" -- ex.
   "o que é o processo `ctfmon.exe`". Resultados de fontes confiáveis vão dizer
   se é normal.
3. **Na dúvida, pergunte a alguém de confiança** que entenda de computador. Não
   há pressa.
4. Se tiver bom motivo para achar que é malware, rode um antivírus de verdade. O
   hightower não é um.

## O que o hightower nunca vai fazer

- Nunca vai mudar, parar ou excluir nada no seu computador. Ele só *olha*.
- Nunca vai usar a internet nem enviar suas informações para lugar nenhum. Tudo
  acontece na sua máquina.
- Nunca vai afirmar, com certeza, que algo é malware. Ele te dá pistas; você
  continua no comando.

## Ainda curioso?

A [wiki do projeto](https://github.com/gsjonio/hightower/wiki) vai mais fundo (é
mais técnica). Para dúvidas, veja o
[FAQ](https://github.com/gsjonio/hightower/wiki/FAQ.pt-BR).
