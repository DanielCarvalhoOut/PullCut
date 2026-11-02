# PullC✂t

Baixa vídeos de uma URL: o vídeo inteiro ou só um trecho, na qualidade escolhida, ou só o áudio.
É uma interface local (só no seu PC) para o [yt-dlp](https://github.com/yt-dlp/yt-dlp). Funciona sozinho ou como a aba de
captura do [Painel](https://github.com/), o estúdio de vídeo que manda o processamento pesado para o Google Colab.

O PullCut tem licença MIT. O motor de download é o yt-dlp (Unlicense, dos autores do yt-dlp), instalado à parte, assim como o FFmpeg.

## Instalar

Pré-requisitos: Windows 10/11, [Node.js 22+](https://nodejs.org) e [FFmpeg](https://ffmpeg.org) (`winget install Gyan.FFmpeg`). Sem dependências npm.

1. Baixe a `yt-dlp.exe` da [release oficial](https://github.com/yt-dlp/yt-dlp/releases) para `bin\`.
2. Confira o SHA-256 com o `SHA2-256SUMS` da mesma release (o que está em `bin\` é o da versão testada, 2026.10.26):
   ```powershell
   (Get-FileHash bin\yt-dlp.exe -Algorithm SHA256).Hash
   ```
3. Opcional: copie `pullcut.config.exemplo.json` para `pullcut.config.json` e ajuste `drive` (a pasta do estúdio no Google Drive) ou acrescente `destinos` (`{ "id": { "nome": "...", "pasta": "..." } }`).

## Como usar

1. Dê dois cliques em **`PullCut.cmd`**. O navegador abre em http://127.0.0.1:4747.
2. Cole a URL e clique em **Analisar**.
3. Escolha:
   - **Tipo:** vídeo ou só áudio (MP3, M4A, WAV)
   - **Qualidade:** as resoluções que o site oferece
   - **Duração:** vídeo inteiro ou um trecho (arraste a faixa ou digite `1:30`, `1:02:03`)
   - **Salvar em:** Downloads do PullCut, HyperFrames (Drive) ou FilmCraft
4. Clique em **Baixar** e acompanhe na lista de downloads.

Para parar, feche a janela minimizada **"PullCut - servidor"**.

## Destinos

| Opção | Pasta |
|---|---|
| Downloads do PullCut | `PullCut\downloads\` |
| HyperFrames (Drive) | `<drive>\HyperFrames\entrada\` |
| FilmCraft (Drive) | `<drive>\FilmCraft\entrada\` |

`<drive>` vem do `pullcut.config.json` (padrão: `G:\Meu Drive\EditorVideos`). Um destino cujo disco não existe aparece desligado.

## Como funciona

- `server.mjs` — servidor Node sem dependências, só em `127.0.0.1` (não fica acessível na rede).
- `public/index.html` — a interface.
- `bin/yt-dlp.exe` — motor de download ([yt-dlp](https://github.com/yt-dlp/yt-dlp) 2026.10.26, SHA256 conferido com a release oficial).
- FFmpeg (instalado pelo winget) — junta vídeo + áudio, corta trechos e converte áudio.

Detalhes:
- Vídeo sai em **MP4 com H.264 + AAC** quando o site oferece, para abrir em qualquer editor sem conversão.
- Trechos usam `--download-sections` com `--force-keyframes-at-cuts`: baixa só o pedaço e o corte é preciso (recodifica as bordas).
- Nome do arquivo: `título [trecho] qualidade [id].ext`.

Atualizar o yt-dlp (os sites mudam com frequência): baixar a nova `yt-dlp.exe` da
[release oficial](https://github.com/yt-dlp/yt-dlp/releases) e conferir o SHA256, ou rodar `bin\yt-dlp.exe -U`.

## Uso responsável

Baixe apenas conteúdo seu, com licença livre (ex.: Creative Commons) ou com autorização do autor, e respeite
os termos de cada site. O yt-dlp não contorna DRM (Netflix, Disney+ etc. não funcionam).

## No Painel

O [Painel](https://github.com/) usa o PullCut como plugin, pela API HTTP (`/api/estado`, `/api/analisar`, `/api/baixar`…), e o liga sozinho se estiver desligado. Para isso, deixe a pasta do PullCut ao lado da do Painel, ou aponte `plugins.pullcut.app` no `painel.config.json`.
