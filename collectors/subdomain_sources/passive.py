from datetime import datetime


from collectors.subdomain_sources.crtsh import (
    get_ct_subdomains
)


# Certspotter existing module
try:

    from collectors.subdomain_sources.certspotter import (
        get_certspotter as get_certspotter_subdomains
    )

except Exception:

    get_certspotter_subdomains = None




def normalize_host(host, domain):

    if not host:
        return None


    host = (
        host
        .lower()
        .strip()
    )


    host = host.replace(
        "*.",
        ""
    )


    if not host.endswith(domain):

        return None


    if host == domain:

        return None


    return host






def run_source(name, function, domain):


    results=set()


    if not function:

        return results



    try:

        print(
            f"[+] Passive source: {name}"
        )


        data=function(
            domain
        )


        for item in data:


            clean=normalize_host(

                item,

                domain

            )


            if clean:

                results.add(clean)



        print(
            f"[+] {name}: {len(results)} hosts"
        )



    except Exception as e:


        print(
            f"[{name} ERROR]",
            e
        )


    return results







def passive_discovery(domain):


    final={}


    sources={



        "certspotter":
            get_certspotter_subdomains,



        "crtsh":
            get_ct_subdomains

    }



    for name,func in sources.items():


        hosts=run_source(

            name,

            func,

            domain

        )


        for host in hosts:


            if host not in final:


                final[host]={

                    "host":host,

                    "sources":[
                        name
                    ]

                }


            else:


                final[host]["sources"].append(
                    name
                )





    return {


        "domain":domain,


        "timestamp":
        datetime.utcnow().isoformat()+"Z",


        "total":
        len(final),


        "assets":
        list(final.values())

    }





if __name__=="__main__":


    target=input(
        "Enter domain: "
    ).strip().lower()



    result=passive_discovery(
        target
    )


    print(
        "\n========== RESULT ==========\n"
    )


    print(
        "Total:",
        result["total"]
    )


    for asset in result["assets"]:


        print(
            asset["host"],
            "=>",
            asset["sources"]
        )