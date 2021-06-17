1) Install python-cim
2) Replace python-cim's cim.py with the FATE version
3) Gather up the CMI db (C:\Windows\System32\wbem\Repository) files. Each set of files needs to be in its own directory per machine.
   a) i.e. objects.data, index.btr, mapping[1-3].map should be in a directory with the machine name
4) Adjust the plugins.ini file. The following lines should match where the wmi_consumerbindings_csv_v0.2.py resides on your system and the options you require.
   consumerbindings=/appl2/wmi/wmi_consumerbindings_csv_v0.2.py
   consumerbindings_opts=--path DIR --type win7 --out OUTFILE
5) adjust the maxthreads in the plugins.ini (see maxthreds) to match your system or desired threads.
6) Run the FATE plugin: ./wmi_v0.2.pl --mntdrive {parent directory with all of the machine files}
7) Output will be in the wmi directory

Output Processing
1) See only the uniq lines: (head -n1 wmi.csv && tail -n +2 wmi.csv | sort -u) > {filename}
2) To see only the uniq lines without the source file path: (head -n1 wmi.csv && cut -d\| -f1-7 wmi.csv | sort -u) > {filename}
