package domain

import (
	"regexp"
	"strings"
)

// sonarKeyPattern são os caracteres que uma project key do SonarQube
// aceita — qualquer outro vira "_". Vive aqui (não em
// infrastructure/sonar_scanner.go, onde nasceu) porque a mesma derivação
// agora tem DOIS consumidores em camadas diferentes: SonarScanner.Execute
// (roda o scanner de verdade, precisa saber em que projeto gravar os
// achados) e transport.toolLink (monta o link "abrir no SonarQube" de um
// achado já persistido, sem rodar scanner nenhum) — domain é a única
// camada que os dois já importam, sem infrastructure precisar vazar pra
// transport nem vice-versa.
var sonarKeyPattern = regexp.MustCompile(`[^A-Za-z0-9._:-]+`)

// SonarProjectKey deriva uma project key estável do SonarQube a partir do
// alvo git de um scan (ignorando o #branch — o Community Edition do
// SonarQube não tem análise multi-branch, então uma chave por
// repositório, não por branch, é o que faz sentido). Determinística:
// escanear o mesmo repositório de novo, ou montar um link pro mesmo
// alvo depois, sempre reproduz a mesma chave.
func SonarProjectKey(target string) string {
	repoURL, _, _ := strings.Cut(target, "#")
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimSuffix(repoURL, ".git")
	return "nix-scan_" + sonarKeyPattern.ReplaceAllString(repoURL, "_")
}
