RDP EVTX Parse Fate Plugin

Parses EVTX event ids outlined in the link below. 
https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/

The tool will create a directory called rdpevtx in the directory where it was ran from. Then it will re-create the directory structure for each file it finds and the output will be the same name as the file with an ".csv" extension on it. 

The idea is to download evtx logs from multiple machines and run the tool against the logs. Once the tool is done, combine all the csv files into a single csv and import it into Excel. Once in Excel sort it by the timestamps, and start the review. 


Setup:
The plugins.ini has an rdpevtx section. Set the evtxparser to the fullpath and filename of the evtxparser (i.e. rdp_evtx_parser_v0.1a.py). Then set the maxthread to two-thirds of the number of cores available (whole numbers please).  



To run as a single plugin:
   ./rdp_evtx_parse_v1.6 --mntdrive {Directory full of evtx logs or directory path with evtx logs}

For example:
   ./rdp_evtx_parse_v1.6 --mntdrive "/mnt/drive/machines evtx"
  
Please use double quotes if there are spaces in the directory names as shown in the example above.

If running on Windows, use \\ in place of \ for directories for the --mntdrive option. 

One the tool has finished the parsed logs are under the ./rdpevtx directory.
