# MISP - McAfee Threat Intelligence Exchange integration

This Integration adds automated containment / response capabilities to the MISP platform with McAfee Threat Intelligence Exchange (TIE).

Based on tagging a script will extract suspicious MD5 hashes from a threat event and will automatically set the external or enterprise reputation in the McAfee TIE database. This effectiley updates all McAfee managed Endpoints.
The MISP tag will get automatically removed after the successfull reputation update.

   <img width="802" alt="Screenshot 2019-10-30 at 18 06 08" src="https://user-images.githubusercontent.com/25227268/67881016-06148e80-fb40-11e9-9cad-54253e965e14.png">

## Component Description
**MISP** threat sharing platform is a free and open source software helping information sharing of threat and cyber security indicators. https://github.com/MISP/MISP

**McAfee Threat Intelligence Exchange** acts as a reputation broker to enable adaptive
threat detection and response. https://www.mcafee.com/enterprise/en-us/products/threat-intelligence-exchange.html

## Prerequisites
MISP platform ([Link](https://github.com/MISP/MISP)) (tested with MISP 2.4.117)

PyMISP ([Link](https://github.com/MISP/PyMISP))
```sh
git clone https://github.com/MISP/PyMISP.git
cd PyMISP/
python setup.py install
```

Requests ([Link](http://docs.python-requests.org/en/master/user/install/#install))

OpenDXL SDK ([Link](https://github.com/opendxl/opendxl-client-python))
```sh
git clone https://github.com/opendxl/opendxl-client-python.git
cd opendxl-client-python/
python setup.py install
```

OpenDXL TIE SDK ([Link](https://github.com/opendxl/opendxl-tie-client-python))
```sh
git clone https://github.com/opendxl/opendxl-tie-client-python.git
cd opendxl-tie-client-python/
python setup.py install
```

McAfee ePolicy Orchestrator, DXL Broker, Active Response

## Configuration
Enter the MISP url and access key in the misp_tie.py file (line 16 and 17).

Enter the tag in the misp_tie.py file (line 19) that should be used to query MISP events.

<img width="474" alt="Screenshot 2019-10-30 at 18 15 36" src="https://user-images.githubusercontent.com/25227268/67881736-57714d80-fb41-11e9-9276-ead5f48afe8a.png">

Create Certificates for OpenDXL and move them into a centralized folder ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epoexternalcertissuance.html)). 

Make sure to authorize the new created certificates in ePO to set McAfee TIE Reputations ([Link](https://opendxl.github.io/opendxl-tie-client-python/pydoc/basicsetreputationexample.html)).

Make sure that the FULL PATH to the config file is entered in line 21 (misp_tie.py).

### Optional

run the script 
```sh
python3.8 /home/misp_tie/misp_tie.py
```

## Summary
MISP contains global, community and locally produced intelligence that can be used to set McAfee TIE reputations (external or enterprise reputations).
