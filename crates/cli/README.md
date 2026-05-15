# gossan

> Part of the [Santh](https://santh.dev) security research ecosystem.

Fast, modular attack surface discovery — subdomains, ports, tech stack, secrets, hidden endpoints, cloud assets — part of the Santh security research ecosystem.

Part of [gossan](https://github.com/santhsecurity/gossan).

## Usage

```bash
# Run a full reconnaissance pipeline on a domain
gossan run example.com --all --output report.json

# Resume a partial scan from a checkpoint
gossan run example.com --resume
```

## License

MIT
