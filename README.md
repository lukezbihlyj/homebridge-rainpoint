# Homebridge RainPoint

A [Homebridge](https://homebridge.io) plugin for RainPoint irrigation systems. Control your water timers, valves, and soil sensors from HomeKit via the RainPoint cloud API.

RainPoint devices are managed through one of two companion apps, each backed by a different cloud:

- **RainPoint Home** — the original app, using the RainPoint Home cloud.
- **RainPoint TY** — the newer app (Tuya-based), using the Tuya IoT cloud.

This plugin supports both. Select the provider that matches the app you set your devices up with.

## Features

| Feature | RainPoint Home | RainPoint TY |
|---------|----------------|--------------|
| Irrigation zone control (on/off) | ✅ | ✅ |
| Soil moisture & temperature sensors | ✅ | ✅ |
| Battery level monitoring | ✅ | ✅ |
| Multi-zone support | ✅ | ✅ |
| IrrigationSystem grouping or flat Valve layout | ✅ | ✅ |
| Automatic token refresh / re-authentication | ✅ | ✅ |
| Persistent cloud session across restarts | ✅ | ✅ |

## Installation

### Via Homebridge UI (Recommended)

1. Search for `homebridge-rainpoint` in the Homebridge UI plugin search
2. Click Install
3. Configure with your RainPoint account credentials

### Via Command Line

```bash
npm install -g homebridge-rainpoint
```

## Configuration

Add the platform to your Homebridge `config.json`. Pick the `provider` that matches the RainPoint app you use.

### RainPoint Home app

```json
{
  "platforms": [
    {
      "platform": "RainPoint",
      "name": "RainPoint",
      "provider": "home",
      "email": "your-email@example.com",
      "password": "your-password",
      "regionHome": "US"
    }
  ]
}
```

### RainPoint TY app

```json
{
  "platforms": [
    {
      "platform": "RainPoint",
      "name": "RainPoint",
      "provider": "ty",
      "email": "your-email@example.com",
      "password": "your-password",
      "regionTy": "AZ",
      "countryCode": "1"
    }
  ]
}
```

### Configuration Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `provider` | No | "home" | Which RainPoint app you use: `"home"` (RainPoint Home) or `"ty"` (RainPoint TY) |
| `email` | Yes | - | Your RainPoint account email |
| `password` | Yes | - | Your RainPoint account password |
| `regionHome` | No | "US" | Region for the RainPoint Home provider: `"US"` (Americas/International) or `"CN"` (China) |
| `regionTy` | No | "AZ" | Region for the RainPoint TY provider: `"AZ"` (Americas), `"EU"` (Europe), `"IN"` (India), or `"CN"` (China) |
| `countryCode` | No | "1" | Dialing code for your country (e.g. `1` for US, `91` for India, `86` for China). Only used with the RainPoint TY provider |
| `name` | No | "RainPoint" | Platform name shown in logs |
| `homeIndex` | No | 0 | Which home to use if you have multiple (0 = first) |
| `pollInterval` | No | 30 | How often to poll for updates (seconds, min 10) |
| `flatValves` | No | false | If true, each zone appears as a standalone Valve accessory instead of grouped under an IrrigationSystem |
| `debugmode` | No | false | Enable debug logging |

> In the Homebridge UI, `regionHome`, `regionTy`, and `countryCode` are shown conditionally based on the selected `provider`.

## HomeKit Accessories

### Irrigation Zones (Valve)
Each irrigation zone/port appears as a Valve accessory in HomeKit with:
- **Active** - Turn the zone on/off
- **InUse** - Indicates if the valve is currently running
- **Set Duration** - Set watering duration in seconds
- **Remaining Duration** - Remaining watering time

### Irrigation System
By default, zones are grouped under an IrrigationSystem accessory. Enable `flatValves` to create standalone Valve accessories instead.

### Soil Sensors
Soil moisture sensors appear as:
- **Humidity Sensor** - Current soil moisture percentage
- **Temperature Sensor** - Current soil temperature (if supported)
- **Battery** - Battery level and low battery alerts

## Naming Conventions

Zone names are derived from the names you set in the RainPoint app (`portDescribe`), prefixed with the device name so multi-valve accessories sort together and their source is obvious.

| Layout | 1-valve device | 2+ valve device |
|--------|----------------|-----------------|
| IrrigationSystem (default) | system = `Back Garden`, valve = `Back Garden: Valve` | system = `Back Garden`, valves = `Back Garden: Left Valve`, `Back Garden: Right Valve` |
| Flat Valves (`flatValves`) | accessory = `Front Garden (Left)` | accessories = `Back Garden: Left Valve`, `Back Garden: Right Valve` |

If a zone has no name in the RainPoint app, it falls back to `Valve N`.

## Running as a Child Bridge

It is recommended to run this plugin as a [child bridge](https://github.com/homebridge/homebridge/wiki/Child-Bridges) for better stability and isolation.

## How It Works

The plugin authenticates with your RainPoint account credentials against the cloud for the selected provider, discovers devices across your homes, polls device status at a configurable interval, and sends control commands to start/stop irrigation zones.

- **RainPoint Home** uses the RainPoint Home cloud API.
- **RainPoint TY** uses the Tuya IoT cloud API, including RSA-encrypted password login and AES-GCM-encrypted request/response payloads.

Device state is encoded using a binary Data Point (DP) system. The plugin parses these hex-encoded states to determine valve on/off status, moisture levels, temperatures, and battery levels.

## License

Apache-2.0

## Feedback & Issues

Please submit any issues or feature requests to the [GitHub Issues](https://github.com/lukezbihlyj/homebridge-rainpoint/issues) page.