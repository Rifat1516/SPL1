import tkinter as tk
from tkinter import ttk,scrolledtext,messagebox,filedialog
import subprocess
import threading
import signal
import os
import socket

class PackAnalyzerUI:
    def __init__(self,root):
        self.root=root
        self.root.title("PackAnalyzer - Ultra Fast Network Analyzer")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e1e1e")

        self.process=None
        self.all_packets_list=[]  
        self.packet_buffer=[] 
        self.packet_details={}

        # --- Top Header ---
        top_frame=tk.Frame(root,bg="#333",pady=10)
        top_frame.pack(fill=tk.X)

        labelFilter=tk.Label(top_frame,text="🔍 Filter:",bg="#333",fg="white",font=("Arial",11))
        labelFilter.pack(side=tk.LEFT,padx=5)
        
        self.search_var=tk.StringVar()
        self.search_var.trace_add("write",self.apply_filter) 
        
        self.search_entry=tk.Entry(top_frame,textvariable=self.search_var,width=12,font=("Arial",11))
        self.search_entry.pack(side=tk.LEFT,padx=5)

        self.btn_start=tk.Button(top_frame,text="▶ Live",command=self.start_live_capture,width=8)
        self.btn_start.pack(side=tk.LEFT,padx=5)

        self.btn_open=tk.Button(top_frame,text="📂 Open PCAP",command=self.open_pcap_file,width=12)
        self.btn_open.pack(side=tk.LEFT,padx=5)

        self.btn_stop=tk.Button(top_frame,text="⏹ Stop",command=self.stop_capture,state=tk.DISABLED,width=6)
        self.btn_stop.pack(side=tk.LEFT,padx=5)

        # Analyzer Box
        labelAnalyze=tk.Label(top_frame,text="🌐 Analyzer (IP):",bg="#333",fg="white",font=("Arial",11))
        labelAnalyze.pack(side=tk.LEFT,padx=10)
        
        self.analyze_var=tk.StringVar()
        self.analyze_entry=tk.Entry(top_frame,textvariable=self.analyze_var,width=15,font=("Arial",11))
        self.analyze_entry.pack(side=tk.LEFT,padx=5)
        
        self.btn_analyze=tk.Button(top_frame,text="🔍 Analyze",command=self.analyze_ip,width=8)
        self.btn_analyze.pack(side=tk.LEFT,padx=5)

        self.btn_syn=tk.Button(top_frame,text="🛡️ SYN Check",command=self.check_syn_flood)
        self.btn_syn.pack(side=tk.RIGHT,padx=15)

        # --- Table View ---
        paned=ttk.PanedWindow(root,orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH,expand=True,padx=10,pady=5)

        tree_frame=tk.Frame(paned)
        paned.add(tree_frame,weight=3)

        cols=("No.","Time","Source","Destination","Protocol","Length","Info")
        self.tree=ttk.Treeview(tree_frame,columns=cols,show="headings",selectmode="browse")
        
        for col in cols:
            self.tree.heading(col,text=col)
            self.tree.column(col,width=100)
            
        self.tree.column("Info",width=500)
        self.tree.pack(fill=tk.BOTH,expand=True,side=tk.LEFT)
        self.tree.bind("<<TreeviewSelect>>",self.on_packet_select)

        sb=ttk.Scrollbar(tree_frame,orient="vertical",command=self.tree.yview)
        sb.pack(side=tk.RIGHT,fill=tk.Y)
        self.tree.configure(yscrollcommand=sb.set)

        self.detail_area=scrolledtext.ScrolledText(paned,bg="#000",fg="white",font=("Consolas",12),height=12)
        paned.add(self.detail_area,weight=2)

    def start_live_capture(self):
        cmdList=["./PackAnalyzer","-L"]
        self.run_capture(cmdList)

    def open_pcap_file(self):
        fileTypes=[("PCAP files","*.pcap"),("All files","*.*")]
        file_path=filedialog.askopenfilename(filetypes=fileTypes)
        
        intPathLength=len(file_path)
        if intPathLength>0:
            cmdList=["./PackAnalyzer","-F",file_path]
            self.run_capture(cmdList)

    def run_capture(self,cmd):
        self.all_packets_list.clear()
        self.packet_buffer.clear()
        
        allChildren=self.tree.get_children()
        self.tree.delete(*allChildren)
        
        self.packet_details.clear()
        
        self.btn_start.config(state=tk.DISABLED)
        self.btn_open.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)

        self.process=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        
        try:
            if "-L" in cmd:
                self.process.stdin.write("0\n") 
                self.process.stdin.flush()
        except: 
            pass

        newThread=threading.Thread(target=self.read_loop,daemon=True)
        newThread.start()
        
        self.root.after(300,self.batch_gui_update)

    def read_loop(self):
        while self.process!=None:
            processStatus=self.process.poll()
            if processStatus!=None:
                break
                
            line=self.process.stdout.readline()
            checkGuiData=line.startswith("GUI_DATA|")
            
            if checkGuiData==True:
                cleanLine=line.strip()
                splitData=cleanLine.split("|")
                data=splitData[1:]
                
                self.all_packets_list.append(data)
                self.packet_buffer.append(data)

    def batch_gui_update(self):
        if self.process==None:
            return 
            
        bufferLength=len(self.packet_buffer)
        if bufferLength>0:
            query=self.search_var.get()
            queryUpper=query.upper()
            
            for data in self.packet_buffer:
                protocolUpper=data[4].upper()
                infoUpper=data[6].upper()
                
                if queryUpper=="" or queryUpper in protocolUpper or queryUpper in infoUpper:
                    rowData=data[:7]
                    self.tree.insert("",tk.END,values=rowData)
            
            treeChildren=self.tree.get_children()
            treeChildrenLength=len(treeChildren)
            
            if treeChildrenLength>0:
                self.tree.yview_moveto(1)
                
            self.packet_buffer.clear() 
            
        self.root.after(300,self.batch_gui_update)

    def apply_filter(self,*args):
        query=self.search_var.get()
        queryUpper=query.upper()
        
        allChildren=self.tree.get_children()
        self.tree.delete(*allChildren)
        
        for pkt in self.all_packets_list:
            protocolUpper=pkt[4].upper()
            infoUpper=pkt[6].upper()
            
            if queryUpper=="" or queryUpper in protocolUpper or queryUpper in infoUpper:
                rowData=pkt[:7]
                self.tree.insert("",tk.END,values=rowData)

    def on_packet_select(self,event):
        try:
            selected_items=self.tree.selection()
            selectedLength=len(selected_items)
            
            if selectedLength==0:
                return

            firstItem=selected_items[0]
            tree_values=self.tree.item(firstItem)['values']
            
            if not tree_values:
                return

            packet_no=str(tree_values[0])
            item_data=list(tree_values) 

            for pkt in self.all_packets_list:
                currentPktNo=str(pkt[0])
                if currentPktNo==packet_no:
                    item_data=pkt
                    break

            self.detail_area.config(state=tk.NORMAL)
            self.detail_area.delete('1.0',tk.END)
            self.detail_area.insert(tk.END,"--- Packet Details ---\n")
            
            itemDataLength=len(item_data)
            
            if itemDataLength>0: 
                self.detail_area.insert(tk.END,f"Packet No  : {item_data[0]}\n")
            if itemDataLength>1: 
                self.detail_area.insert(tk.END,f"Timestamp  : {item_data[1]}\n")
            if itemDataLength>2: 
                self.detail_area.insert(tk.END,f"Source IP  : {item_data[2]}\n")
            if itemDataLength>7: 
                self.detail_area.insert(tk.END,f"Source MAC : {item_data[7]}\n")
            if itemDataLength>3: 
                self.detail_area.insert(tk.END,f"Dest IP    : {item_data[3]}\n")
            if itemDataLength>8: 
                self.detail_area.insert(tk.END,f"Dest MAC   : {item_data[8]}\n")
            if itemDataLength>4: 
                self.detail_area.insert(tk.END,f"Protocol   : {item_data[4]}\n")
            if itemDataLength>9: 
                self.detail_area.insert(tk.END,f"TTL        : {item_data[9]}\n")
            if itemDataLength>5: 
                self.detail_area.insert(tk.END,f"Length     : {item_data[5]} bytes\n")

            self.detail_area.insert(tk.END,"\n--- Protocol Specific Info ---\n")
            
            if itemDataLength>6:
                self.detail_area.insert(tk.END,f"{item_data[6]}\n\n")

            self.detail_area.insert(tk.END,"--- Full Packet Hex & ASCII Dump ---\n")
            dashLine="-"*60
            self.detail_area.insert(tk.END,dashLine+"\n")
            
            if itemDataLength>10:
                rawHexData=str(item_data[10])
                hex_data=rawHexData.replace("\\n","\n")
                self.detail_area.insert(tk.END,hex_data)
            else:
                self.detail_area.insert(tk.END,"No Hex Data Available\n")
                
        except Exception as e:
            errorMsg=str(e)
            self.detail_area.insert(tk.END,f"\n[!] Error displaying details: {errorMsg}")

    def stop_capture(self):
        if self.process!=None:
            try: 
                processId=self.process.pid
                os.kill(processId,signal.SIGINT)
            except: 
                pass
            self.process=None
            
        self.btn_start.config(state=tk.NORMAL)
        self.btn_open.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    # --- Analyze IP Function ---
    def analyze_ip(self):
        try:
            raw_target_ip=self.analyze_var.get()
            target_ip=raw_target_ip.strip()
            
            targetIpLength=len(target_ip)
            if targetIpLength==0:
                messagebox.showwarning("Warning","Please enter a Destination IP address first.")
                return

            matching_packets=[]
            for pkt in self.all_packets_list:
                pktLength=len(pkt)
                if pktLength>3:
                    destIp=pkt[3]
                    if destIp==target_ip:
                        matching_packets.append(pkt)
                        
            packet_count=len(matching_packets)

            result_window=tk.Toplevel(self.root)
            result_window.title(f"Analysis for {target_ip}")
            result_window.geometry("650x500") 
            result_window.configure(bg="#1e1e1e")

            if packet_count>0:
                try:
                    hostnameInfo=socket.gethostbyaddr(target_ip)
                    hostname=hostnameInfo[0]
                    host_info=hostname
                except socket.herror:
                    host_info="(Hostname not resolved/Hidden)"
                
                header_text=f"✅ SUCCESS: IP was accessed!\n🌐 Host: {host_info}\n📦 Total Packets Exchanged: {packet_count}"
                
                headerLabel=tk.Label(result_window,text=header_text,bg="#1e1e1e",fg="white",font=("Arial",12,"bold"),justify=tk.CENTER)
                headerLabel.pack(pady=10)
                
                listLabel=tk.Label(result_window,text="--- Detailed Packet List ---",bg="#1e1e1e",fg="white",font=("Arial",10,"italic"))
                listLabel.pack()

                txt_area=scrolledtext.ScrolledText(result_window,bg="#000",fg="white",font=("Consolas",10),height=15)
                txt_area.pack(fill=tk.BOTH,expand=True,padx=15,pady=10)
                
                for pkt in matching_packets:
                    pktLen=len(pkt)
                    if pktLen>6:
                        protocolName=pkt[4]
                        packetLen=pkt[5]
                        packetInfo=pkt[6]
                        
                        entry=f"[{protocolName}] Len: {packetLen} bytes | Info: {packetInfo}\n"
                        txt_area.insert(tk.END,entry)
                        
                        separatorLine="-"*70
                        txt_area.insert(tk.END,separatorLine+"\n") 
                
                txt_area.config(state=tk.DISABLED) 
            else:
                msg=f"❌ ERROR: IP {target_ip}\nwas NOT accessed in this session."
                errorLabel=tk.Label(result_window,text=msg,bg="#1e1e1e",fg="white",font=("Arial",13,"bold"))
                errorLabel.pack(expand=True)
            
            okButton=tk.Button(result_window,text="OK",command=result_window.destroy,width=10)
            okButton.pack(pady=10)
            
        except Exception as e:
            errorString=str(e)
            messagebox.showerror("Error",f"Could not analyze IP: {errorString}")

    # --- SYN Check Function ---
    def check_syn_flood(self):
        try:
            syn_counts={}
            for pkt in self.all_packets_list:
                pktLength=len(pkt)
                if pktLength>6:
                    packetInfo=pkt[6]
                    if "[SYN]" in packetInfo:
                        sourceIp=pkt[2]
                        if sourceIp in syn_counts:
                            currentCount=syn_counts[sourceIp]
                            newCount=currentCount+1
                            syn_counts[sourceIp]=newCount
                        else:
                            syn_counts[sourceIp]=1

            attack_detected=False
            for count in syn_counts.values():
                if count>20:
                    attack_detected=True
                    break

            report_window=tk.Toplevel(self.root)
            report_window.title("🛡️ SYN Flood Security Report")
            report_window.geometry("650x450")
            report_window.configure(bg="#1e1e1e")
            
            dictLength=len(syn_counts)

            if dictLength==0 or attack_detected==False:
                banner_bg="#28a745" 
                banner_text="✅ SYSTEM SECURE: TRAFFIC IS NORMAL"
            else:
                banner_bg="#dc3545" 
                banner_text="⚠️ WARNING: SYN FLOOD ATTACK DETECTED!"

            bannerLabel=tk.Label(report_window,text=banner_text,bg=banner_bg,fg="white",font=("Arial",14,"bold"),pady=10)
            bannerLabel.pack(fill=tk.X,padx=10,pady=15)

            columns=("IP Address","SYN Packets Sent","Status")
            tree_frame=tk.Frame(report_window,bg="#1e1e1e")
            tree_frame.pack(fill=tk.BOTH,expand=True,padx=15,pady=5)

            tree=ttk.Treeview(tree_frame,columns=columns,show="headings",height=10)
            tree.heading("IP Address",text="Source IP Address")
            tree.heading("SYN Packets Sent",text="SYN Count")
            tree.heading("Status",text="Threat Level")

            tree.column("IP Address",width=200,anchor=tk.CENTER)
            tree.column("SYN Packets Sent",width=150,anchor=tk.CENTER)
            tree.column("Status",width=150,anchor=tk.CENTER)

            sb=ttk.Scrollbar(tree_frame,orient="vertical",command=tree.yview)
            sb.pack(side=tk.RIGHT,fill=tk.Y)
            tree.configure(yscrollcommand=sb.set)
            tree.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)

            tree.tag_configure("normal",foreground="#0f0",background="#000") 
            tree.tag_configure("attack",foreground="#ff4444",background="#330000") 
            tree.tag_configure("empty",foreground="white",background="#000")

            if dictLength==0:
                tree.insert("",tk.END,values=("N/A","0","Safe"),tags=("empty",))
            else:
                # 1st Year Student Friendly Sorting Method (Bubble Sort Idea)
                listItems=[]
                for ip,count in syn_counts.items():
                    tupleItem=(ip,count)
                    listItems.append(tupleItem)
                    
                totalItems=len(listItems)
                for i in range(totalItems):
                    for j in range(i+1,totalItems):
                        count1=listItems[i][1]
                        count2=listItems[j][1]
                        
                        if count2>count1:
                            temp=listItems[i]
                            listItems[i]=listItems[j]
                            listItems[j]=temp
                            
                for sortedItem in listItems:
                    ip=sortedItem[0]
                    count=sortedItem[1]
                    
                    if count>20:
                        status="⚠️ ATTACK!"
                        tag="attack"
                    else:
                        status="Normal"
                        tag="normal"
                        
                    tree.insert("",tk.END,values=(ip,count,status),tags=(tag,))

            closeButton=tk.Button(report_window,text="Close Report",command=report_window.destroy,font=("Arial",11,"bold"),width=15)
            closeButton.pack(pady=15)
                      
        except Exception as e:
            errorStr=str(e)
            messagebox.showerror("Error",f"Failed to generate SYN report: {errorStr}")

if __name__=="__main__":
    root=tk.Tk()
    app=PackAnalyzerUI(root)
    root.mainloop()