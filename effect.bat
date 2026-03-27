@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S1-CVE-2015-5122_windows.dot.txt --alert payload.exe --collection attack_pattern_s1_s2s3s4 --output data/cost_results/S1_payload_results1
@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S2-CVE-2015-3105_windows.dot.txt --alert payload.exe --collection attack_pattern_s2_s1s3s4 --output data/cost_results/S2_payload_results1
@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S3-CVE-2017-11882_windows.dot.txt --alert payload.exe --collection attack_pattern_s3_s1s2s4 --output data/cost_results/S3_payload_results1
@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S4-CVE-2017-0199_windows_py.dot.txt --alert pypayload.exe --collection attack_pattern_s4_s1s2s3 --output data/cost_results/S4_payload_results1

python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S1-CVE-2015-5122_windows.dot.txt --alert payload.exe  --collection attack_pattern_s1_s2s3s4 --output data/cost_results/S1_payload_results1_noresoning
python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S2-CVE-2015-3105_windows.dot.txt --alert payload.exe --collection attack_pattern_s2_s1s3s4 --output data/cost_results/S2_payload_results1_noresoning
python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S3-CVE-2017-11882_windows.dot.txt --alert payload.exe --collection attack_pattern_s3_s1s2s4 --output data/cost_results/S3_payload_results1_noresoning
python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S4-CVE-2017-0199_windows_py.dot.txt --alert payload.exe --collection attack_pattern_s4_s1s2s3 --output data/cost_results/S4_payload_results1_noresoning

@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S1-CVE-2015-5122_windows.dot.txt --alert 192.168.223.3 --collection attack_pattern_s1_s2s3s4 --output data/time_windos_cost_results/S1_IP_results1
@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S2-CVE-2015-3105_windows.dot.txt --alert 192.168.223.3 --collection attack_pattern_s2_s1s3s4 --output data/cost_results/S2_IP_results1
@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S3-CVE-2017-11882_windows.dot.txt --alert 192.168.223.3 --collection attack_pattern_s3_s1s2s4 --output data/cost_results/S3_IP_results1
@REM python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_S4-CVE-2017-0199_windows_py.dot.txt --alert 192.168.223.3 --collection attack_pattern_s4_s1s2s3 --output data/cost_results/S4_IP_results1


python attack_Investigation_byLLM.py --log_file data/logs/P1_logs_E1_P1-CVE-2017-0144_windows.txt.txt --alert spoolsv.exe --collection attack_pattern_m6_m1m2m3m4m5 --output data/results/P1_payload.txt
python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_M6-CVE-2017-11882_windows_h2.dot.txt --alert 192.168.223.3 --collection attack_pattern_m6_m1m2m3m4m5 --output data/results/M6h2_results_IN_m12345_cover_IP.txt
python attack_Investigation_byLLM.py --log_file data/logs/seq_graph_training_preprocessed_logs_M6-CVE-2017-11882_windows_h2.dot.txt --alert 0xalsaheel.com --collection attack_pattern_m6_m1m2m3m4m5 --output data/results/M6h2_results_IN_m12345_cover_Domain.txt


python attack_Investigation_byLLM.py --log_file data/logs/EB-CVE-2017-0144_windows_P1.txt --alert 192.168.17.128 --collection attack_pattern_m6_m1m2m3m4m5 --output data/results/P1_IP.txt

python attack_Investigation_byLLM.py --log_file data/logs/EB-CVE-2017-0144_windows_P2.txt --alert spoolsv.exe --collection attack_pattern_m6_m1m2m3m4m5 --output data/results/P2_payload.txt

python attack_Investigation_byLLM.py --log_file data/logs/EB-CVE-2017-0144_windows_P2.txt --alert 192.168.17.128 --collection attack_pattern_m6_m1m2m3m4m5 --output data/results/P2_IP.txt
