# Architektúra Áttekintés

Ez a dokumentum egy magas szintű áttekintést nyújt a sémafordító és aláíró infrastruktúráról.

## Alapfilozófia

A keretrendszer elsődleges célja egy irányított, biztonságos és reprodukálható munkafolyamat létrehozása a verziózott sémák kezelésére. Minden nem fejlesztői séma kriptográfiailag alá van írva, biztosítva ezzel az integritását és egy ellenőrizhető audit nyomvonalat.

- **Irányítás (Governance):** Minden sémának meg kell felelnie egy központi meta-sémának.
- **Biztonság:** Az aláírást a HashiCorp Vault kezeli, biztosítva, hogy a privát kulcsok soha ne kerüljenek ki a rendszerből.
- **Reprodukálhatóság:** A teljes környezet Docker konténerekben fut, garantálva, hogy minden fejlesztő és CI/CD pipeline azonos környezetben működik.

## Komponensek Felépítése

A repository több kulcsfontosságú könyvtárra van osztva:

- **/schemas**: A "forrás" sémákat tartalmazza. A fejlesztők itt végeznek módosításokat. Az `index.yaml` fájl a központi **meta-meta-séma**, amely az összes többi sémára vonatkozó szabályokat definiálja.
- **/dependencies**: Kiadott, aláírt és verziózott sémákat tárol, amelyeket más sémák validátorként használhatnak. Ezek az építőelemek.
- **/release**: Végleges, aláírt, alkalmazás-specifikus sémákat tartalmaz, amelyek készen állnak az alkalmazások általi felhasználásra.
- **/tools**: A keretrendszer működéséhez szükséges összes szkriptet és eszközt tartalmazza, beleértve a Python fordítót, a kiadási folyamat shell szkriptjeit és a Git hook-okat.
- **/p_venv**: A Python függőségek helyi gyorsítótára, amelyet a `pip-tools` kezel. Ez a könyvtár nincs a Git-be commitolva.

## A Kiadási és Aláírási Folyamat

Az alábbi diagram a forrásfájlból történő aláírt séma-artefaktum létrehozásának folyamatát szemlélteti.

```
+----------------+      +----------------+      +----------------------+      +---------------------+
|   Fejlesztő    |----->|  make release  |----->|   Docker Konténer    |----->|   Aláírt Artefaktum |
| (Sémát módosít)|      | (Makefile-ben) |      |  (tools/compiler.py) |      | (pl. dependency.yaml) |
+----------------+      +----------------+      +----------+-----------+      +---------------------+
                                                           |
                                                           | (HTTPS API Hívás)
                                                           v
                                                  +----------------+
                                                  |  Vault Szerver |
                                                  | (Aláírás & KV) |
                                                  +----------------+
```

**A folyamat lépései:**

1.  **Fejlesztői Művelet:** Egy fejlesztő módosít egy sémafájlt a `/schemas` könyvtárban.
2.  **Kiadás Kezdeményezése:** A fejlesztő futtatja a `make release-dependency VERSION=v1.2.3` parancsot.
3.  **Konténer Végrehajtás:** A `Makefile` parancs végrehajtja a `tools/release.sh` szkriptet a `builder` Docker konténeren belül.
4.  **Fordítás és Aláírás:**
    - A `release.sh` szkript meghívja a `tools/compiler.py` szkriptet.
    - A fordító validálja a forrás sémát a deklarált meta-sémája alapján.
    - Kiszámolja a séma `spec` blokkjának ellenőrzőösszegét (checksum).
    - Lekéri az aláíró tanúsítványt és a kiállítói tanúsítványt a Vault KV tárolójából.
    - Létrehoz egy metaadat blokkot, abból egy hash-t képez, és **csak a hash-t** küldi el a Vault Transit Engine-nek aláírásra.
    - A Vault visszaad egy aláírást.
5.  **Artefaktum Összeállítása:** A fordító összeállítja a végleges YAML fájlt, amely tartalmazza az eredeti sémát, az új verziószámot, az ellenőrzőösszeget, az aláírást és a `createdBy` blokkot a tanúsítvány részleteivel.
6.  **Git Műveletek:** A `release.sh` szkript létrehoz egy új Git ágat, commitolja az aláírt artefaktumot, és létrehoz egy GPG-aláírt Git taget a kiadási verzióhoz.
