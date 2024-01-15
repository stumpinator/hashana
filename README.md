Hashana is a collection of functions and classes for storing and quickly retrieving hashes.

The original intent of this project was to convert the National Software Reference Library (NSRL) Reference Data Set (RDS) into a more compact and portable format. Tools used to accomplish this task were slightly generalized to be applicable in other project.

The tools provided can convert the entire RDS (100s of GBs) into approximately 13GB containing just unique hashes and their respective file sizes. This is customizable and could be made even smaller if less information is required. Adding the raw data to a sqlite database and indexing will add another 20-25GB, but the entire data set remains <= 40GB. The indexes are optional but make querying the entire 170M+ hashes very quick and responsive.

A front end of sorts is provided that allows easy querying via json. A zeromq front end for microservices and network applications is also available if you have the zmq package installed.


Example to convert the RDS data (may take 1 hour or more depending on hardware):

rds_list = [r"C:\NSRL\RDS_2023.12.1_modern_minimal.db", r"C:\NSRL\RDS_2023.12.1_legacy_minimal.db", r"C:\NSRL\RDS_2023.12.1_android_minimal.db", r"C:\NSRL\RDS_2023.12.1_ios_minimal.db"]
HashanaRDSReader.make_hashana_db(rds_list, r"C:\NSRL\hashana_23.12.1.db")


Links:
https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/rds-query
