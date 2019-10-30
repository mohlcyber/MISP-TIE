# MISP - McAfee Threat Intelligence Exchange Integration

This Integration adds automated containment / response capabilities to the MISP platform with McAfee Threat Intelligence Exchange (TIE).

Based on tagging a script will extract suspicious MD5 hashes from a threat event and will automatically set the external or enterprise reputation in the McAfee TIE database. This effectiley updates all McAfee managed Endpoints.
The MISP tag will get automatically removed after the successfull reputation update.

