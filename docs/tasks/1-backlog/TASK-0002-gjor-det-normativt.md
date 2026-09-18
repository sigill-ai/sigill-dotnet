# TASK-0002: Gjør det normativt

EPIC-0001, ledd 2. Status: Backlog — skrives ferdig etter TASK-0001.
Starter kun etter ja fra eier og Raymond.

## Formål

Ta det som virket i prøvekjøringen og gjøre det til noe andre kan bygge
mot: spesifikasjon, skjema, byteidentiske testvektorer og en pakke som
kan publiseres. Innholdet skrives fra koden i TASK-0001, ikke fra notatet
alene.

## Omfang, foreløpig

1. Tre spesifikasjoner og tre JSON Schema i `spec/`, etter mønsteret i
   `ai-evidence-envelope-v2.md`, med kjedereglene og bindingsregelen fra
   notatet 5.2 og 4.4 som normative setninger. Feltnavn låses her.
2. Kanoniseringsvektorer i `spec/test-vectors/` for de tre profilene
   (v2 §11 klasse 1), og verifikasjonsvektorer for de fem
   sabotasjetestene som ikke ble tatt i TASK-0001 (notatet 8.3).
3. Krysshenvisning fra v2 §3.4 om at kjedesemantikken er fastsatt.
4. Pakkemetadata og forhåndsversjon for sidepakken. Publisering er egen
   eierbeslutning.
5. Beslutningene B1, B2, B5 og B6 tas før tasken starter og skrives inn
   her.
6. Bestilling av speiling til sigill-python som egen task der.

## Akseptansekriterier, foreløpig

1. Alle eksempler validerer mot sitt skjema; `_generate.py` reproduserer
   vektorene byte for byte.
2. Alle åtte sabotasjetester grønne uten nettverk.
3. Omfanget er revidert mot det TASK-0001 faktisk viste.
