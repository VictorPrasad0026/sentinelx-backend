from orchestrator.pipeline import SentinelPipeline

def main():
    domain = input("Target Domain: ").strip()
    SentinelPipeline().scan(domain)

if __name__ == "__main__":
    main()