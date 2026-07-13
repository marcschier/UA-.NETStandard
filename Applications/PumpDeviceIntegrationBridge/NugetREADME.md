# PumpDeviceIntegrationBridge

A standalone **OPC UA → OpenUSD** client (the *bridge* / *connector* actor of the draft
**OPC UA — OpenUSD Bindings** companion specification). It connects to an OPC UA server,
discovers the OpenUSD representation and its live bindings from the server's address
space, subscribes to the bound Variables, converts the values, and authors a live USD
override layer (`live.usda`). Composed over a base USD asset, that layer drives a pump
**rendered with live data** in `usdview` or NVIDIA Omniverse — with **no domain-specific
code** in the bridge or the renderer.

This project is the client half of the `PumpDeviceIntegrationServer` end-to-end sample.

## What it does

```
PumpDeviceIntegrationServer            (OPC UA server: PumpType + OpenUSD bindings)
        │  Server/OpenUSD/Representations  (discovery)
        ▼
PumpDeviceIntegrationBridge  ──►  UsdFileSink ──►  live.usda   (runtime override layer)
                                          │  subLayers
                                          ▼
                                       stage.usda  =  live.usda  +  Plant.usda
                                          │
                                          ▼
                                 usdview / NVIDIA Omniverse   (the rendered live pump)
```

The bridge starts at the well-known `Server/OpenUSD/Representations` registry (Part 1
discovery), reads each `OpenUsdLiveBinding` (`SourceNodeId`, target prim/property,
`RenderTargetKind`, `Scale`), subscribes, applies the conversion, and writes the target
USD attribute. It never needs to know "pump" — the same binary works for any conforming
server.

## The three live bindings (pump sample)

| Source (Pump measurement) | USD target | Kind | Visible effect |
|---|---|---|---|
| `MassFlow` | `/Plant/Pumps/P101/Impeller` · `xformOp:rotateZ` | Rotation | impeller angle |
| `BearingTemperature` | `/Plant/Pumps/P101/Body` · `primvars:displayColor` | DisplayColor | body colour (blue→red) |
| `DifferentialPressure` | `/Plant/Pumps/P101/StatusLight/Mat/Surface` · `inputs:emissiveColor` | EmissiveColor | status-light glow |

## Prerequisites

- **.NET SDK 10** — to build and run the server + bridge.
- A USD viewer: **usdview** (from a full OpenUSD build or NVIDIA Omniverse's `usdview`), or
  **NVIDIA Omniverse** (USD Composer / Kit) for an RTX render with continuous `.live`
  updates. The `usd-core` PyPI wheel provides the `pxr` Python modules for validation but
  **not** the `usdview` GUI.
- The base USD asset (`Plant.usda`) and composed stage (`stage.usda`) from the companion
  spec repo: `marcschier/opcua-drafts` →
  `core-specs/extras/openusd-binding/examples/pumps/`.

## Run it end-to-end

### 1. Build

```bash
dotnet build Applications/PumpDeviceIntegrationServer/PumpDeviceIntegrationServer.csproj -c Release -f net10.0
dotnet build Applications/PumpDeviceIntegrationBridge/PumpDeviceIntegrationBridge.csproj -c Release -f net10.0
```

### 2. Prepare a working folder with the base asset

```bash
mkdir ~/pump-live
cp <opcua-drafts>/core-specs/extras/openusd-binding/examples/pumps/Plant.usda ~/pump-live/
cp <opcua-drafts>/core-specs/extras/openusd-binding/examples/pumps/stage.usda ~/pump-live/
```

`stage.usda` sublayers `live.usda` (stronger) over `Plant.usda`.

### 3. Start the server (terminal 1)

```bash
dotnet run --project Applications/PumpDeviceIntegrationServer -c Release -f net10.0 -- --host localhost --port 62810
```

Wait for `OPC UA server listening at opc.tcp://localhost:62810/PumpDeviceIntegrationServer.`
The pump simulation drives `MassFlow`, `BearingTemperature`, and `DifferentialPressure`,
which is what makes the render *live*.

### 4. Run the bridge (terminal 2)

```bash
dotnet run --project Applications/PumpDeviceIntegrationBridge -c Release -f net10.0 -- \
  --server opc.tcp://localhost:62810/PumpDeviceIntegrationServer --out ~/pump-live/live.usda --insecure
```

Options: `--server <opc.tcp url>` (default `opc.tcp://localhost:62542/PumpDeviceIntegrationServer`),
`--out <live.usda>`, `--seconds N` (run for a fixed time instead of until Ctrl+C), and
`--insecure`. The bridge is **secure by default** (encrypted, signed channel with server-certificate
trust required, per spec §9). `--insecure` opts into an unsecured endpoint and blanket certificate
acceptance — appropriate only for this localhost demo, whose server uses a self-signed certificate.
Omit `--insecure` and place the server certificate in the bridge's trusted store for a secured run.

It rewrites `live.usda` on every value change, e.g.:

```usda
over "Plant" { over "Pumps" { over "P101" {
    over "Impeller" { double xformOp:rotateZ = 0.0538 }
    over "Body" { color3f[] primvars:displayColor = [(1.0000, 0.0000, 0.0000)] }
    over "StatusLight" { over "Mat" { over "Surface" {
        color3f inputs:emissiveColor = (0.1000, 1.0000, 0.2000) } } }
} } }
```

### 5. Open the rendered live pump

- **usdview:** `usdview ~/pump-live/stage.usda` — a cylindrical body, a two-blade impeller,
  and a status light. usdview loads a snapshot; press **`R`** (Reload All Layers) to pull
  the bridge's latest values.
- **NVIDIA Omniverse:** open `~/pump-live/stage.usda` in USD Composer — the override layer
  updates the viewport **continuously** under RTX (impeller spins, body warms toward red,
  status light glows).

> The emissive glow needs a material-aware renderer (Omniverse RTX, or usdview with Storm);
> `displayColor` and the transform render everywhere.

## Validate composition without a GUI

With only `usd-core` installed:

```bash
python - <<'PY'
from pxr import Usd, UsdGeom
s = Usd.Stage.Open("stage.usda")
g = lambda p, a: s.GetPrimAtPath(p).GetAttribute(a).Get()
print("rotateZ     :", g("/Plant/Pumps/P101/Impeller", "xformOp:rotateZ"))
print("displayColor:", g("/Plant/Pumps/P101/Body", "primvars:displayColor"))
print("emissive    :", g("/Plant/Pumps/P101/StatusLight/Mat/Surface", "inputs:emissiveColor"))
PY
```

## How it maps to the specification

- **Discovery** — the bridge starts at `Server/OpenUSD/Representations` (base spec §4.2),
  never at "the pump". One binary serves any conforming server.
- **Bindings** — each `OpenUsdLiveBinding` declares `SourceNodeId`, target prim/property,
  `RenderTargetKind`, and `Scale`; the bridge reads them and applies the conversion
  (§5.7–§5.8).
- **Layering** — OPC UA is the single mapping authority; the base USD asset is never
  modified. Live values live in a composed override layer (the equivalent of an Omniverse
  Nucleus `.live` layer, Part 3).

The generic companion specification and the full step-by-step guide live in
`marcschier/opcua-drafts` under `core-specs/openusd-binding/`.
