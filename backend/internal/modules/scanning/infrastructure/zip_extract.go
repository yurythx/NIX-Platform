package infrastructure

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// maxZipUncompressedBytes limita o total de bytes DESCOMPRIMIDOS gravados
// em disco a partir de um único upload — defesa contra "zip bomb" (um
// arquivo pequeno que se expande pra gigabytes, esgotando o disco do
// worker). O limite é aplicado contra os bytes REALMENTE copiados
// (io.LimitReader), nunca contra o campo UncompressedSize64 do cabeçalho
// do zip — esse campo é informado pelo próprio arquivo e não é confiável
// (nada impede um .zip malicioso de mentir sobre ele). var, não const:
// zip_extract_test.go reduz temporariamente pra não precisar gerar um
// .zip de 500MB de verdade só pra testar o limite.
var maxZipUncompressedBytes int64 = 500 * 1024 * 1024 // 500MB

// ZipExtractor implementa domain.ZipExtractor (Fase 10 — projeto criado
// por upload .zip) — o par de cloneShallow (git_clone.go) pro caso de
// upload em vez de git: em vez de clonar uma URL, extrai os bytes de um
// .zip pra um diretório novo dentro do volume compartilhado
// scanning_workspace, pra ficar visível também pros sidecars
// (trivy-scanner/gitleaks-scanner), do mesmo jeito que um clone git fica.
type ZipExtractor struct {
	// baseDir é onde o diretório de extração nasce — mesmo papel do
	// baseDir de cloneShallow: "" usa o padrão do SO (os.MkdirTemp),
	// ScanningWorkspaceDir em produção.
	baseDir string
	logger  *slog.Logger
}

func NewZipExtractor(baseDir string, logger *slog.Logger) *ZipExtractor {
	return &ZipExtractor{baseDir: baseDir, logger: logger}
}

var _ domain.ZipExtractor = (*ZipExtractor)(nil)

// ExtractZip valida zipBytes e extrai pra um diretório novo — defende
// contra "zip slip" (uma entrada como "../../etc/cron.d/x", ou um caminho
// absoluto, que escreveria fora do diretório de destino se não fosse
// checada — a mesma classe de ataque que validateHost já previne pro caso
// do git/SSRF, adaptada pra path em vez de host) e contra "zip bomb" (ver
// maxZipUncompressedBytes acima). Quem chama é responsável por invocar o
// cleanup retornado (sempre não nil quando err é nil) — mesmo contrato de
// cloneShallow.
func (e *ZipExtractor) ExtractZip(zipBytes []byte) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp(e.baseDir, "nix-upload-*")
	if err != nil {
		return "", nil, fmt.Errorf("scanning: create temp dir: %w", err)
	}
	cleanup = func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			e.logger.Warn("scanning: failed to clean up upload temp dir", slog.String("dir", dir), slog.Any("error", rmErr))
		}
	}

	if err := extractZipTo(zipBytes, dir); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

func extractZipTo(zipBytes []byte, dir string) error {
	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return apperrors.Validation(fmt.Sprintf("scanning: invalid .zip file: %s", err))
	}

	cleanDir := filepath.Clean(dir)
	budget := maxZipUncompressedBytes
	for _, f := range r.File {
		destPath := filepath.Join(dir, f.Name)
		if destPath != cleanDir && !strings.HasPrefix(destPath, cleanDir+string(os.PathSeparator)) {
			return apperrors.Validation(fmt.Sprintf("scanning: .zip entry %q escapes the extraction directory", f.Name))
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return fmt.Errorf("scanning: create dir from zip entry: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("scanning: create parent dir from zip entry: %w", err)
		}

		written, err := extractZipFile(f, destPath, budget)
		if err != nil {
			return err
		}
		budget -= written
		if budget < 0 {
			return apperrors.Validation("scanning: .zip uncompressed size exceeds the limit")
		}
	}
	return nil
}

// extractZipFile grava no máximo budget+1 bytes de f (via io.LimitReader)
// — o "+1" é só pra conseguir DETECTAR que o arquivo era maior que o
// orçamento restante (io.Copy devolve exatamente budget+1, não menos),
// nunca gravado de fato num arquivo final válido nesse caso (extractZipTo
// trata written > budget original como erro logo em seguida).
func extractZipFile(f *zip.File, destPath string, budget int64) (written int64, err error) {
	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("scanning: open zip entry %q: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("scanning: create file from zip entry: %w", err)
	}
	defer out.Close()

	written, err = io.Copy(out, io.LimitReader(rc, budget+1))
	if err != nil {
		return written, fmt.Errorf("scanning: write file from zip entry: %w", err)
	}
	return written, nil
}
