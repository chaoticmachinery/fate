Windows Prefetch Mass Triage Parser

Description: Parses Windows prefetch files

Requires:
1) libscca


The tool will create a directory called prefetch in the directory where it was ran from. Then it will re-create the directory structure for each file it finds and the output will be the same name as the file with an ".csv" extension on it. 

The idea is to download pretch files from multiple machines and run the tool against the files. Once the tool is done, combine all the csv files into a single csv and import it into Excel. Once in Excel sort it by the timestamps, and start the review. 


Setup:
The plugins.ini has an prefetch section. Set the prefetchparser to the fullpath and filename of the prefetch parser (i.e. w10pf_parser_v0.1.py). Then set the maxthread to two-thirds of the number of cores available (whole numbers please).  



To run as a single plugin:
   ./prefetch_v0.1.pl  --mntdrive {Directory full of evtx logs or directory path with evtx logs}

For example:
   ./prefetch_v0.1.pl  --mntdrive "/mnt/drive/machines evtx"
  
Please use double quotes if there are spaces in the directory names as shown in the example above.

If running on Windows, use \\ in place of \ for directories for the --mntdrive option. 

One the tool has finished the parsed logs are under the ./prefetch directory.
