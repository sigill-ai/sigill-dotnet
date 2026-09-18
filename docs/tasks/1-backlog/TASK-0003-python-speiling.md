# TASK-0003: Speiling av agentprofilene til sigill-python

EPIC-0001, ledd 3. Status: **Parkert** 18.09.2026 (eierbeslutning). Speilingen
gir ingenting til ende-til-ende-testingen og dobler kostnaden ved hver
endring så lenge koden er sannheten. Tas opp etter eiers ja til å gå videre
med initiativet. Ingenting går tapt: vektor 10 med kanoniske bytes,
forventet resultat og sabotasjekopier er fasiten en senere port oversettes
mot. Gjøres på en initiativgren i sigill-python når den tid kommer.

## Formål

Samme tre profiler i Python, byteidentisk med .NET, slik CONTRIBUTING.md
krever for alt i `spec/`.

## Omfang

1. Kopier `spec/` fra denne grenen inn i sigill-python (vendoring, byte
   for byte), inkludert `test-vectors/10-agent-controlled-run/`.
2. Pakke `sigill-agent` (arbeidsnavn) over `sigill` med samme fire
   byggeklosser: Control Artifact, kjøring med kjede og avslutning,
   Control Evaluation, verifikator med resultatflaten fra
   `agent-profiles-common-v1.md` §4.
3. Tester som leser vektor 10: kanoniske bytes, `hashV[0]`, intakt sett
   mot `expected-result.json`, de åtte sabotasjetestene.

## Akseptanse

Porten gir identiske kanoniske bytes for alle ni konvolutter i vektor 10
og identisk verifikasjonsresultat for det intakte settet.
