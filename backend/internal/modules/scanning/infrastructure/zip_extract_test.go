package infrastructure

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
)

// buildZip monta um .zip em memória a partir de um mapa nome->conteúdo —
// helper compartilhado por todos os testes deste arquivo.
func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip.Create(%q): %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtractZip_WritesFilesPreservingStructure(t *testing.T) {
	zipBytes := buildZip(t, map[string]string{
		"go.mod":          "module example.com/app\n",
		"internal/app.go": "package internal\n",
	})

	extractor := NewZipExtractor(t.TempDir(), testLogger(t))
	dir, cleanup, err := extractor.ExtractZip(zipBytes)
	if err != nil {
		t.Fatalf("ExtractZip: %v", err)
	}
	defer cleanup()

	modContent, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("read extracted go.mod: %v", err)
	}
	if string(modContent) != "module example.com/app\n" {
		t.Errorf("go.mod content = %q, want the exact bytes from the zip entry", modContent)
	}

	appContent, err := os.ReadFile(filepath.Join(dir, "internal", "app.go"))
	if err != nil {
		t.Fatalf("read extracted internal/app.go: %v", err)
	}
	if string(appContent) != "package internal\n" {
		t.Errorf("internal/app.go content = %q, unexpected", appContent)
	}
}

func TestExtractZip_CleanupRemovesDir(t *testing.T) {
	zipBytes := buildZip(t, map[string]string{"a.txt": "hello"})

	extractor := NewZipExtractor(t.TempDir(), testLogger(t))
	dir, cleanup, err := extractor.ExtractZip(zipBytes)
	if err != nil {
		t.Fatalf("ExtractZip: %v", err)
	}
	cleanup()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("dir %q still exists after cleanup, want it removed", dir)
	}
}

func TestExtractZip_ZipSlip_ParentDirEscape_IsRejected(t *testing.T) {
	zipBytes := buildZip(t, map[string]string{"../../etc/cron.d/evil": "* * * * * root touch /tmp/pwned"})

	extractor := NewZipExtractor(t.TempDir(), testLogger(t))
	_, _, err := extractor.ExtractZip(zipBytes)
	if err == nil {
		t.Fatal("expected an error for a zip entry escaping the extraction directory via ../")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeValidation {
		t.Errorf("err = %v, want a VALIDATION_ERROR apperrors.Error", err)
	}
}

// TestExtractZip_AbsolutePathEntry_StaysInsideDestDir cobre um entendimento
// real sobre filepath.Join, não uma suposição: Join(dir, "/etc/passwd")
// NÃO produz "/etc/passwd" — produz "dir/etc/passwd" (Join sempre trata o
// segundo argumento como um componente a concatenar e limpar, nunca como
// "substitui o caminho inteiro" só porque começa com "/"). Uma entrada de
// zip com path absoluto já fica presa dentro do diretório de destino por
// construção, sem precisar de nenhuma checagem extra além da que já existe
// pra "../" — este teste prova isso em vez de só assumir.
func TestExtractZip_AbsolutePathEntry_StaysInsideDestDir(t *testing.T) {
	zipBytes := buildZip(t, map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/sh"})

	extractor := NewZipExtractor(t.TempDir(), testLogger(t))
	dir, cleanup, err := extractor.ExtractZip(zipBytes)
	if err != nil {
		t.Fatalf("ExtractZip: %v, want an absolute-path entry to land safely inside dir, not be rejected", err)
	}
	defer cleanup()

	content, err := os.ReadFile(filepath.Join(dir, "etc", "passwd"))
	if err != nil {
		t.Fatalf("read extracted etc/passwd inside dir: %v", err)
	}
	if string(content) != "root:x:0:0::/root:/bin/sh" {
		t.Errorf("content = %q, unexpected", content)
	}
}

func TestExtractZip_InvalidZipBytes_IsRejected(t *testing.T) {
	extractor := NewZipExtractor(t.TempDir(), testLogger(t))
	_, _, err := extractor.ExtractZip([]byte("this is not a zip file"))
	if err == nil {
		t.Fatal("expected an error for bytes that are not a valid zip archive")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeValidation {
		t.Errorf("err = %v, want a VALIDATION_ERROR apperrors.Error", err)
	}
}

func TestExtractZip_UncompressedSizeOverLimit_IsRejected(t *testing.T) {
	// Escreve o conteúdo real (não confia no cabeçalho UncompressedSize64
	// — ver o comentário de maxZipUncompressedBytes) maior que o
	// orçamento, temporariamente reduzido só pra este teste não precisar
	// gerar um .zip de 500MB de verdade.
	orig := maxZipUncompressedBytes
	maxZipUncompressedBytes = 10
	defer func() { maxZipUncompressedBytes = orig }()

	zipBytes := buildZip(t, map[string]string{"big.txt": "this content is way more than ten bytes long"})

	extractor := NewZipExtractor(t.TempDir(), testLogger(t))
	_, _, err := extractor.ExtractZip(zipBytes)
	if err == nil {
		t.Fatal("expected an error when the real extracted content exceeds the uncompressed size limit")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.CodeValidation {
		t.Errorf("err = %v, want a VALIDATION_ERROR apperrors.Error", err)
	}
}
