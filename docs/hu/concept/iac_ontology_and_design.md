# CIC IaC Ontológia és Tervezési Alapelvek

Ez a dokumentum a Central Infra Core (CIC) Infrastructure as Code (IaC) rendszerének fogalmi modelljét, tervezési döntéseit és működési logikáját rögzíti. A leírás a rendszer tervezési fázisában született döntéseken alapul.

## 1. Alapfilozófia

A CIC IaC nem egy Kubernetes-klón és nem egy hagyományos konfiguráció-menedzsment eszköz. A rendszer alapelvei:
*   **Gráf-alapú megközelítés**: Az infrastruktúra nem fa, hanem gráf.
*   **Állapot-vezérelt**: A "Desired State" (elvárt) és "Actual State" (valós) szigorú szétválasztása.
*   **Platform-független**: A modell absztrakciós szintje független a konkrét technológiától (bare-metal, VM, konténer).
*   **Single Source of Truth**: A `base-repo` és a sémák definiálják az igazságot.

## 2. Az Alapmodell: Relay - Host - Service

A rendszer három elsődleges objektumtípusra épül, amelyek a gráf csomópontjait alkotják.

### 2.1. Relay (Közvetítő / Csomópont)
A Relay a rendszer irányító és aggregáló eleme.
*   **Szerepe**: Nem "tartalmazza" a hostokat vagy szolgáltatásokat (mint egy mappa), hanem *látja* és *kezeli* őket (inventory).
*   **Működése**: Állapotot publikál felfelé, és konfigurációt (policy-t) érvényesít lefelé.
*   **Struktúra**: Saját `spec`-je csak a Relay működését írja le. A kezelt elemeket `hosts` és `services` listákban hivatkozza.

### 2.2. Host (Futtató Környezet)
Infrastrukturális alapegység, amely számítási kapacitást biztosít.
*   **Típusai**: Lehet fizikai gép (bare-metal), virtuális gép (VM), vagy akár egy konténer-környezet node-ja.
*   **Jellemzői**: Rendelkezik operációs rendszerrel, alapvető szolgáltatásokkal (agent, DNS), és identitással.

### 2.3. Service (Szolgáltatás)
Funkcionális egység, amely értéket állít elő.
*   **Viszonya a Hosthoz**: A Service *nem* a Host része, hanem a Hosthoz van *rendelve*. Egy Service futhat több Hoston is.
*   **Rekurzió**: Egy Service maga is lehet komplex rendszer (pl. egy adatbázis-fürt), amely további al-szolgáltatásokat igényel.

## 3. Virtualizációs és Provider Minta

A rendszer kezeli azt a kettősséget, amikor egy infrastruktúra-elem (pl. VM) egyszerre szolgáltatás-kimenet és futtató környezet.

### 3.1. Provider mint Service
A virtualizációs platform (pl. Proxmox, vSphere, OpenStack) a CIC modellben **Service**-ként jelenik meg.
*   Feladata: Erőforrások (VM-ek) létrehozása és menedzselése.

### 3.2. VM mint Host Contract
A Provider által létrehozott VM kettős természete így oldódik fel:
1.  **Provider szemszögéből**: Egy menedzselt objektum a Provider `spec`-jében (`vms` lista). Itt definiáljuk a CPU, RAM, Disk paramétereket.
2.  **CIC szemszögéből**: Egy **Host**, amelyre szolgáltatásokat lehet telepíteni.

**Megvalósítás (VM Entry struktúra):**
*   `meta`: Provider-specifikus azonosítók (pl. VMID).
*   `spec`: Erőforrás-konfiguráció (Provider-specifikus).
*   `host`: **Host Contract**. Ez írja le a létrejövő gép CIC-kompatibilis tulajdonságait (OS, base services, identitás), ami alapján a Relay hostként tudja kezelni.

## 4. Állapotkezelés és Git

A rendszer a Git-et használja az állapotok verziókövetésére és szétválasztására.

*   **Desired State (Elvárt állapot)**: Ez az IaC repository tartalma. Amit a mérnök leír és commitol. (Pl. "Legyen egy VM 4GB RAM-mal").
*   **Actual State (Valós állapot)**: Ez egy külön Git ág (vagy repo), ahová a rendszer (Relay/Agent) visszairja a mért adatokat. (Pl. "A VM IP címe 10.0.0.5, állapota: running").
*   **Feldolgozás**: A `default` értékek és az öröklődés (override) nem az IaC fájlokban tárolódnak statikusan, hanem a feldolgozási pipeline során érvényesülnek.

## 5. Base Repo és Template Rendszer

A konzisztencia biztosítása érdekében a rendszer egy központi `base-repo`-ra épül.
*   **Szerepe**: Ez a "Single Source of Truth". Tartalmazza az ontológiát, a sémákat és a feldolgozási szabályokat.
*   **Használata**: Minden projekt (IaC, Schema, Code) ebből a template-ből származik Git worktree segítségével. Ez garantálja, hogy mindenki ugyanazt a fogalmi rendszert és eszközöket használja.

## 6. Monolitikus vs. Elosztott Leírás

A rendszer rugalmasan kezeli a leíró fájlok szerkezetét.

*   **Elosztott (Moduláris)**: A Relay, a Hostok és a Service-ek külön fájlokban (`relay.yaml`, `hosts/*.yaml`, `services/*.yaml`) helyezkednek el. Ez a javasolt struktúra nagyobb rendszereknél az átláthatóság és a Git-konfliktusok elkerülése érdekében.
*   **Monolitikus (Egyfájlos)**: Lehetőség van arra is, hogy egyetlen YAML fájlban (pl. egy "nagy" `relay.yaml`-ben vagy egy Provider Service leírásában) definiáljuk a teljes struktúrát. Ebben az esetben a `hosts` és `services` listák nem fájl-referenciákat, hanem beágyazott objektumokat tartalmaznak. A feldolgozó logika (pipeline) képes ezt a struktúrát "szétlapítani" (flatten) és gráfként értelmezni.
