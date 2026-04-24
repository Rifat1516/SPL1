#include<gtk/gtk.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<signal.h>

GtkWidget *window;
GtkWidget *treeview;
GtkListStore *liststore;
GtkTreeModel *filter_model; 
GtkWidget *detail_area;
GtkTextBuffer *text_buffer;

GtkWidget *search_entry;
GtkWidget *analyze_entry;
GtkWidget *btn_start;
GtkWidget *btn_open;
GtkWidget *btn_stop;

GtkWidget *attack_entry;
GtkWidget *btn_attack;
GtkWidget *btn_stop_attack;

// নতুন ডোমেইন সার্চের জন্য ভেরিয়েবল
GtkWidget *domain_entry;

GPid child_pid;
int process_running;
int syn_alert_shown;

int gui_syn_threshold=100; 

enum
{
    COL_NO=0,
    COL_TIME,
    COL_SRC,
    COL_DST,
    COL_PROTO,
    COL_LEN,
    COL_INFO,
    COL_MAC_SRC,
    COL_MAC_DST,
    COL_TTL,
    COL_HEX,
    NUM_COLS
};

void apply_custom_theme()
{
    GtkCssProvider *provider;
    provider=gtk_css_provider_new();
    
    char cssData[2500];
    cssData[0]='\0';
    
    strcat(cssData,"window { background-color:#1e1e1e; }\n");
    strcat(cssData,"box { background-color:#1e1e1e; }\n");
    strcat(cssData,"paned { background-color:#1e1e1e; }\n");
    strcat(cssData,"label { color:#ffffff; font-family:Arial; font-size:14px; }\n");
    strcat(cssData,"button { background-image:none; background-color:#ffffff; color:#000000; border:1px solid #aaaaaa; padding:5px 10px; font-weight:bold; }\n");
    strcat(cssData,"button label { color:#000000; font-weight:bold; }\n");
    strcat(cssData,"button:hover { background-color:#e0e0e0; }\n");
    strcat(cssData,"button:disabled { background-color:#333333; color:#888888; border:1px solid #222222; }\n");
    strcat(cssData,"button:disabled label { color:#888888; }\n");
    strcat(cssData,"entry { background-color:#333333; color:#ffffff; caret-color:#ffffff; border:1px solid #555555; }\n");
    strcat(cssData,"treeview { background-color:#1e1e1e; color:#ffffff; }\n");
    strcat(cssData,"treeview:selected { background-color:#2a4d69; color:#ffffff; }\n");
    strcat(cssData,"treeview header button { background-color:#2b2b2b; border:1px solid #444444; }\n");
    strcat(cssData,"treeview header button label { color:#ffffff; font-weight:bold; }\n");
    strcat(cssData,"textview text { background-color:#000000; color:#ffffff; font-family:monospace; font-size:14px; }\n");
    strcat(cssData,"scrolledwindow { background-color:#1e1e1e; }\n");
    
    int endMarker;
    endMarker=-1;
    
    GError *error;
    error=NULL;
    
    gtk_css_provider_load_from_data(provider,cssData,endMarker,&error);
    
    GdkScreen *screen;
    screen=gdk_screen_get_default();
    
    guint priority;
    priority=GTK_STYLE_PROVIDER_PRIORITY_APPLICATION;
    
    GtkStyleProvider *styleProvider;
    styleProvider=GTK_STYLE_PROVIDER(provider);
    
    gtk_style_context_add_provider_for_screen(screen,styleProvider,priority);
    
    g_object_unref(provider);
}

void close_window_callback(GtkWidget *widget,gpointer data)
{
    GtkWidget *winToClose;
    winToClose=GTK_WIDGET(data);
    gtk_widget_destroy(winToClose);
}

void search_domain(GtkWidget *widget,gpointer data)
{
    GtkEntry *castEntry;
    castEntry=GTK_ENTRY(domain_entry);
    
    const gchar *target_domain;
    target_domain=gtk_entry_get_text(castEntry);
    
    int domLength;
    domLength=strlen(target_domain);
    
    if(domLength==0)
    {
        return;
    }
    
    GtkTreeModel *treeModel;
    treeModel=GTK_TREE_MODEL(liststore);
    
    GtkTreeIter iter;
    gboolean valid;
    valid=gtk_tree_model_get_iter_first(treeModel,&iter);
    
    int matchCount;
    matchCount=0;
    
    int endMarker;
    endMarker=-1;
    
    char *detailsBuffer = (char*)malloc(300000);
    if(detailsBuffer == NULL) return;
    detailsBuffer[0]='\0';
    int current_len = 0;
    
    while(valid!=0)
    {
        gchar *time;
        gchar *info;
        
        gtk_tree_model_get(treeModel,&iter,COL_TIME,&time,COL_INFO,&info,endMarker);
        
        gchar *infoLower;
        infoLower=g_ascii_strdown(info,endMarker);
        
        gchar *searchLower;
        searchLower=g_ascii_strdown(target_domain,endMarker);
        
        char *findMatch;
        findMatch=strstr(infoLower,searchLower);
        
        if(findMatch!=NULL)
        {
            matchCount++;
            
            char lineBuf[500];
            char *formatStr;
            formatStr="🕒 Time: %s | %s\n------------------------------------------------------------\n";
            sprintf(lineBuf,formatStr,time,info);
            
            int addLen;
            addLen=strlen(lineBuf);
            
            if(current_len+addLen<299000)
            {
                strcpy(detailsBuffer + current_len, lineBuf);
                current_len += addLen;
            }
        }
        
        g_free(time);
        g_free(info);
        g_free(infoLower);
        g_free(searchLower);
        
        valid=gtk_tree_model_iter_next(treeModel,&iter);
    }
    
    GtkWidget *resWin;
    GtkWindowType winTop;
    winTop=GTK_WINDOW_TOPLEVEL;
    resWin=gtk_window_new(winTop);
    
    GtkWindow *castResWin;
    castResWin=GTK_WINDOW(resWin);
    
    char titleBuf[500];
    char *titleFormat;
    titleFormat="Web History: %s";
    sprintf(titleBuf,titleFormat,target_domain);
    
    gtk_window_set_title(castResWin,titleBuf);
    
    int winW;
    winW=650;
    int winH;
    winH=400;
    gtk_window_set_default_size(castResWin,winW,winH);
    
    GtkOrientation orientVert;
    orientVert=GTK_ORIENTATION_VERTICAL;
    int spacingFive;
    spacingFive=5;
    
    GtkWidget *vbox;
    vbox=gtk_box_new(orientVert,spacingFive);
    
    GtkContainer *castWinCont;
    castWinCont=GTK_CONTAINER(resWin);
    gtk_container_add(castWinCont,vbox);
    
    char headerText[1000];
    if(matchCount>0)
    {
        char *successFmt;
        successFmt="✅ FOUND: User visited '%s'\nTotal Connections Logged: %d times";
        sprintf(headerText,successFmt,target_domain,matchCount);
    }
    else
    {
        char *errorFmt;
        errorFmt="❌ NOT FOUND: No record of visiting '%s' in this session.";
        sprintf(headerText,errorFmt,target_domain);
    }
    
    GtkWidget *headerLabel;
    headerLabel=gtk_label_new(headerText);
    
    GtkBox *castVbox;
    castVbox=GTK_BOX(vbox);
    
    gboolean expandFalse;
    expandFalse=FALSE;
    gboolean fillFalse;
    fillFalse=FALSE;
    guint paddingTen;
    paddingTen=10;
    
    gtk_box_pack_start(castVbox,headerLabel,expandFalse,fillFalse,paddingTen);
    
    GtkWidget *scrollArea;
    scrollArea=gtk_scrolled_window_new(NULL,NULL);
    
    gboolean expandTrue;
    expandTrue=TRUE;
    gboolean fillTrue;
    fillTrue=TRUE;
    
    gtk_box_pack_start(castVbox,scrollArea,expandTrue,fillTrue,paddingTen);
    
    GtkWidget *txtView;
    txtView=gtk_text_view_new();
    
    GtkTextView *castTxtView;
    castTxtView=GTK_TEXT_VIEW(txtView);
    gtk_text_view_set_editable(castTxtView,expandFalse);
    
    GtkTextBuffer *tBuf;
    tBuf=gtk_text_view_get_buffer(castTxtView);
    gtk_text_buffer_set_text(tBuf,detailsBuffer,endMarker);
    
    GtkContainer *castScrollCont;
    castScrollCont=GTK_CONTAINER(scrollArea);
    gtk_container_add(castScrollCont,txtView);
    
    GtkWidget *okBtn;
    char *okLabel;
    okLabel="Close Report";
    okBtn=gtk_button_new_with_label(okLabel);
    
    char *clickedSig;
    clickedSig="clicked";
    g_signal_connect(okBtn,clickedSig,G_CALLBACK(close_window_callback),resWin);
    
    gtk_box_pack_start(castVbox,okBtn,expandFalse,fillFalse,paddingTen);
    
    gtk_widget_show_all(resWin);
    free(detailsBuffer); // মেমরি লিক রোধ
}

void launch_attack(GtkWidget *widget,gpointer data)
{
    GtkEntry *castEntry;
    castEntry=GTK_ENTRY(attack_entry);
    
    const gchar *target_ip;
    target_ip=gtk_entry_get_text(castEntry);
    
    int ipLen;
    ipLen=strlen(target_ip);
    
    if(ipLen==0)
    {
        return; 
    }
    
    char cmd[1000];
    char *cmdFormat;
    cmdFormat="PATH=/opt/homebrew/sbin:/usr/local/sbin:$PATH hping3 -S --flood -V -p 80 %s > /dev/null 2>&1 &";
    sprintf(cmd,cmdFormat,target_ip);
    
    system(cmd); 
    
    GtkWindow *parentWin;
    parentWin=GTK_WINDOW(window);
    
    GtkDialogFlags flags;
    flags=GTK_DIALOG_DESTROY_WITH_PARENT;
    
    GtkMessageType msgType;
    msgType=GTK_MESSAGE_INFO;
    
    GtkButtonsType btnType;
    btnType=GTK_BUTTONS_OK;
    
    char msgBuf[1500];
    char *msgFmt;
    msgFmt="🔥 Stealth Attack Launched!\n\nTarget IP: %s\n\nঅ্যাটাকটি ব্যাকগ্রাউন্ডে নীরবে চলছে। কয়েক সেকেন্ড অপেক্ষা করুন, আপনার সিস্টেম অ্যাটাকটি ধরে লাল অ্যালার্ট দিয়ে দেবে!";
    sprintf(msgBuf,msgFmt,target_ip);
    
    GtkWidget *dialog;
    dialog=gtk_message_dialog_new(parentWin,flags,msgType,btnType,"%s",msgBuf);
    
    GtkDialog *castDialog;
    castDialog=GTK_DIALOG(dialog);
    
    gtk_dialog_run(castDialog);
    gtk_widget_destroy(dialog);
}

void stop_attack(GtkWidget *widget,gpointer data)
{
    char *killCmd;
    killCmd="killall -9 hping3 > /dev/null 2>&1"; 
    system(killCmd);
    
    GtkWindow *parentWin;
    parentWin=GTK_WINDOW(window);
    
    GtkDialogFlags flags;
    flags=GTK_DIALOG_DESTROY_WITH_PARENT;
    
    GtkMessageType msgType;
    msgType=GTK_MESSAGE_INFO;
    
    GtkButtonsType btnType;
    btnType=GTK_BUTTONS_OK;
    
    char *msgTxt;
    msgTxt="🛑 Attack Stopped Successfully.";
    
    GtkWidget *dialog;
    dialog=gtk_message_dialog_new(parentWin,flags,msgType,btnType,"%s",msgTxt);
    
    GtkDialog *castDialog;
    castDialog=GTK_DIALOG(dialog);
    
    gtk_dialog_run(castDialog);
    gtk_widget_destroy(dialog);
}

gboolean filter_vis_func(GtkTreeModel *model,GtkTreeIter *iter,gpointer data)
{
    GtkEntry *castSearchEntry;
    castSearchEntry=GTK_ENTRY(search_entry);
    
    const gchar *search_text;
    search_text=gtk_entry_get_text(castSearchEntry);
    
    GtkEntry *castAnalyzeEntry;
    castAnalyzeEntry=GTK_ENTRY(analyze_entry);
    
    const gchar *analyze_text;
    analyze_text=gtk_entry_get_text(castAnalyzeEntry);
    
    int searchLen;
    searchLen=strlen(search_text);
    
    int analyzeLen;
    analyzeLen=strlen(analyze_text);
    
    if(searchLen==0 && analyzeLen==0)
    {
        return TRUE;
    }
    
    gchar *proto;
    proto=NULL;
    gchar *info;
    info=NULL;
    gchar *src;
    src=NULL;
    gchar *dst;
    dst=NULL;
    
    int endMarker;
    endMarker=-1;
    
    gtk_tree_model_get(model,iter,COL_PROTO,&proto,COL_INFO,&info,COL_SRC,&src,COL_DST,&dst,endMarker);
    
    gboolean isMainMatch;
    isMainMatch=TRUE;
    
    gboolean isAnalyzeMatch;
    isAnalyzeMatch=TRUE;
    
    if(searchLen>0)
    {
        isMainMatch=FALSE;
        
        gchar *protoLower;
        protoLower=g_ascii_strdown(proto,endMarker);
        
        gchar *infoLower;
        infoLower=g_ascii_strdown(info,endMarker);
        
        gchar *srcLower;
        srcLower=g_ascii_strdown(src,endMarker);
        
        gchar *dstLower;
        dstLower=g_ascii_strdown(dst,endMarker);
        
        gchar *searchLower;
        searchLower=g_ascii_strdown(search_text,endMarker);
        
        gboolean prefixMatch;
        prefixMatch=g_str_has_prefix(protoLower,searchLower);
        
        if(prefixMatch!=0)
        {
            isMainMatch=TRUE;
        }
        
        char *foundInSrc;
        foundInSrc=strstr(srcLower,searchLower);
        if(foundInSrc!=NULL)
        {
            isMainMatch=TRUE;
        }
        
        char *foundInDst;
        foundInDst=strstr(dstLower,searchLower);
        if(foundInDst!=NULL)
        {
            isMainMatch=TRUE;
        }
        
        if(searchLen>1)
        {
            char *foundInInfo;
            foundInInfo=strstr(infoLower,searchLower);
            if(foundInInfo!=NULL)
            {
                isMainMatch=TRUE;
            }
        }
        
        g_free(protoLower);
        g_free(infoLower);
        g_free(srcLower);
        g_free(dstLower);
        g_free(searchLower);
    }
    
    if(analyzeLen>0)
    {
        isAnalyzeMatch=FALSE;
        
        gboolean srcStarts;
        srcStarts=g_str_has_prefix(src,analyze_text);
        
        gboolean dstStarts;
        dstStarts=g_str_has_prefix(dst,analyze_text);
        
        if(srcStarts!=0)
        {
            isAnalyzeMatch=TRUE;
        }
        
        if(dstStarts!=0)
        {
            isAnalyzeMatch=TRUE;
        }
    }
    
    g_free(proto);
    g_free(info);
    g_free(src);
    g_free(dst);
    
    gboolean finalVisibility;
    finalVisibility=FALSE;
    
    if(isMainMatch!=0)
    {
        if(isAnalyzeMatch!=0)
        {
            finalVisibility=TRUE;
        }
    }
    
    return finalVisibility;
}

void on_search_changed(GtkWidget *widget,gpointer data)
{
    GtkTreeModelFilter *castFilter;
    castFilter=GTK_TREE_MODEL_FILTER(filter_model);
    
    gtk_tree_model_filter_refilter(castFilter);
}

// ⚠️ ক্র্যাশ ও হ্যাং হওয়া ফিক্সড: O(N^2) লুপ এবং Buffer Overflow বাদ দেওয়া হয়েছে
void on_row_selected(GtkTreeSelection *selection,gpointer data)
{
    GtkTreeIter iter;
    GtkTreeModel *model;
    
    int isSelected;
    isSelected=gtk_tree_selection_get_selected(selection,&model,&iter);
    
    if(isSelected!=0)
    {
        gchar *no;
        gchar *time;
        gchar *src;
        gchar *dst;
        gchar *proto;
        gchar *len;
        gchar *info;
        gchar *mac_src;
        gchar *mac_dst;
        gchar *ttl;
        gchar *hex;
        
        int endMarker;
        endMarker=-1;
        
        gtk_tree_model_get(model,&iter,COL_NO,&no,COL_TIME,&time,COL_SRC,&src,COL_DST,&dst,COL_PROTO,&proto,COL_LEN,&len,COL_INFO,&info,COL_MAC_SRC,&mac_src,COL_MAC_DST,&mac_dst,COL_TTL,&ttl,COL_HEX,&hex,endMarker);
        
        char *details = (char*)malloc(300000);
        if(details == NULL) return;
        details[0]='\0';
        int current_len = 0;
        
        strcpy(details,"--- Packet Details ---\n");
        current_len = strlen(details);
        
        char tempBuf[2000];
        
        char *labelNo;
        labelNo="Packet No  : ";
        sprintf(tempBuf,"%s%s\n",labelNo,no);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelTime;
        labelTime="Timestamp  : ";
        sprintf(tempBuf,"%s%s\n",labelTime,time);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelSrc;
        labelSrc="Source IP  : ";
        sprintf(tempBuf,"%s%s\n",labelSrc,src);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelMacSrc;
        labelMacSrc="Source MAC : ";
        sprintf(tempBuf,"%s%s\n",labelMacSrc,mac_src);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelDst;
        labelDst="Dest IP    : ";
        sprintf(tempBuf,"%s%s\n",labelDst,dst);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelMacDst;
        labelMacDst="Dest MAC   : ";
        sprintf(tempBuf,"%s%s\n",labelMacDst,mac_dst);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelProto;
        labelProto="Protocol   : ";
        sprintf(tempBuf,"%s%s\n",labelProto,proto);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelTtl;
        labelTtl="TTL        : ";
        sprintf(tempBuf,"%s%s\n",labelTtl,ttl);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        char *labelLen;
        labelLen="Length     : ";
        sprintf(tempBuf,"%s%s bytes\n",labelLen,len);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        strcpy(details + current_len, "\n--- Protocol Specific Info ---\n"); current_len = strlen(details);
        sprintf(tempBuf,"%s\n\n",info);
        strcpy(details + current_len, tempBuf); current_len += strlen(tempBuf);
        
        strcpy(details + current_len, "--- Full Packet Hex & ASCII Dump ---\n------------------------------------------------------------\n"); current_len = strlen(details);
        
        int hexLen;
        hexLen=strlen(hex);
        int i;
        
        for(i=0;i<hexLen;i++)
        {
            if(current_len >= 299990) break;
            
            char currentChar;
            currentChar=hex[i];
            
            char nextChar;
            nextChar=hex[i+1];
            
            if(currentChar=='\\' && nextChar=='n')
            {
                details[current_len++] = '\n';
                i++;
            }
            else
            {
                details[current_len++] = currentChar;
            }
        }
        details[current_len] = '\0';
        
        gtk_text_buffer_set_text(text_buffer,details,endMarker);
        
        free(details);
        g_free(no);
        g_free(time);
        g_free(src);
        g_free(dst);
        g_free(proto);
        g_free(len);
        g_free(info);
        g_free(mac_src);
        g_free(mac_dst);
        g_free(ttl);
        g_free(hex);
    }
}

gboolean read_core_output(GIOChannel *source,GIOCondition condition,gpointer data)
{
    gchar *line;
    gsize length;
    GError *error;
    error=NULL;
    
    GIOStatus status;
    status=g_io_channel_read_line(source,&line,&length,NULL,&error);
    
    GIOStatus normalStatus;
    normalStatus=G_IO_STATUS_NORMAL;
    
    if(status==normalStatus)
    {
        // 1. সাধারণ ডাটা পার্সিং
        gboolean isGuiData;
        char *prefixDataCheck="GUI_DATA|";
        isGuiData=g_str_has_prefix(line,prefixDataCheck);
        
        if(isGuiData!=0)
        {
            char *parsedData[12];
            int index=0;
            char *rest=line;
            char *token;
            char delim[2]="|";
            
            token=strtok_r(rest,delim,&rest);
            while(token!=NULL && index<11)
            {
                token=strtok_r(rest,delim,&rest);
                if(token!=NULL)
                {
                    parsedData[index]=token;
                    index++;
                }
            }
            if(index>=11)
            {
                int appendIndex=-1;
                gtk_list_store_insert_with_values(liststore,NULL,appendIndex,COL_NO,parsedData[0],COL_TIME,parsedData[1],COL_SRC,parsedData[2],COL_DST,parsedData[3],COL_PROTO,parsedData[4],COL_LEN,parsedData[5],COL_INFO,parsedData[6],COL_MAC_SRC,parsedData[7],COL_MAC_DST,parsedData[8],COL_TTL,parsedData[9],COL_HEX,parsedData[10],-1);
            }
        }
        
        // 2. SYN Flood অ্যালার্ট
        gboolean isAlertData;
        char *prefixAlertCheck="GUI_ALERT|SYN_FLOOD|";
        isAlertData=g_str_has_prefix(line,prefixAlertCheck);
        
        if(isAlertData!=0 && syn_alert_shown==0)
        {
            syn_alert_shown=1;
            char *restAlert=line;
            char delimAlert[2]="|";
            
            strtok_r(restAlert,delimAlert,&restAlert);
            strtok_r(restAlert,delimAlert,&restAlert);
            char *countStr=strtok_r(restAlert,delimAlert,&restAlert);
            
            char alertMsg[1000];
            sprintf(alertMsg,"🚨 LIVE ATTACK DETECTED!\n\nA SYN Flood attack is currently hitting your network!\nHalf-Open Connections: %s",countStr);
            
            GtkWidget *dialog=gtk_message_dialog_new(GTK_WINDOW(window),GTK_DIALOG_DESTROY_WITH_PARENT,GTK_MESSAGE_WARNING,GTK_BUTTONS_OK,"%s",alertMsg);
            gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
        }

        gboolean isSigAlert;
        char *prefixSigCheck="GUI_ALERT|SIGNATURE_MATCH|";
        isSigAlert=g_str_has_prefix(line,prefixSigCheck);
        
        if(isSigAlert!=0)
        {
            char *restAlert=line;
            char delimAlert[2]="|";
            
            strtok_r(restAlert,delimAlert,&restAlert); 
            strtok_r(restAlert,delimAlert,&restAlert); 
            
            char *threatName = strtok_r(restAlert,delimAlert,&restAlert);
            char *attackerIp = strtok_r(restAlert,delimAlert,&restAlert);
            
            char alertMsg[1500];
            sprintf(alertMsg,"🛑 CRITICAL THREAT BLOCKED!\n\nOur High-Speed Aho-Corasick Engine detected a malicious signature in the payload.\n\nThreat Rule: %s\nSource IP: %s\n\nAction Taken: Logged & Flagged.", threatName, attackerIp);
            
            GtkWidget *dialog=gtk_message_dialog_new(GTK_WINDOW(window),GTK_DIALOG_DESTROY_WITH_PARENT,GTK_MESSAGE_ERROR,GTK_BUTTONS_OK,"%s",alertMsg);
            gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
        }
        
        g_free(line);
        return TRUE;
    }
    return FALSE;
}
void run_capture(char *cmdArray[])
{
    syn_alert_shown=0;
    
    gtk_list_store_clear(liststore);
    
    int endMarker;
    endMarker=-1;
    char *emptyText;
    emptyText="";
    gtk_text_buffer_set_text(text_buffer,emptyText,endMarker);
    
    gboolean stateFalse;
    stateFalse=FALSE;
    gboolean stateTrue;
    stateTrue=TRUE;
    
    gtk_widget_set_sensitive(btn_start,stateFalse);
    gtk_widget_set_sensitive(btn_open,stateFalse);
    gtk_widget_set_sensitive(btn_stop,stateTrue);
    
    gint standard_out;
    GError *error;
    error=NULL;
    
    GSpawnFlags flags;
    flags=G_SPAWN_SEARCH_PATH;
    
    gboolean spawnCheck;
    spawnCheck=g_spawn_async_with_pipes(NULL,cmdArray,NULL,flags,NULL,NULL,&child_pid,NULL,&standard_out,NULL,&error);
    
    if(spawnCheck!=0)
    {
        process_running=1;
        
        GIOChannel *channel;
        channel=g_io_channel_unix_new(standard_out);
        
        GIOCondition condIn;
        condIn=G_IO_IN;
        
        g_io_add_watch(channel,condIn,(GIOFunc)read_core_output,NULL);
        g_io_channel_unref(channel);
    }
    else
    {
        printf("Error starting process\n");
    }
}

void start_live_capture(GtkWidget *widget,gpointer data)
{
    char *cmdArray[3];
    cmdArray[0]="./PackAnalyzer";
    cmdArray[1]="-L";
    cmdArray[2]=NULL;
    
    run_capture(cmdArray);
}

void open_pcap_file(GtkWidget *widget,gpointer data)
{
    GtkWindow *parentWindow;
    parentWindow=GTK_WINDOW(window);
    
    GtkFileChooserAction actionOpen;
    actionOpen=GTK_FILE_CHOOSER_ACTION_OPEN;
    
    int respCancel;
    respCancel=GTK_RESPONSE_CANCEL;
    int respAccept;
    respAccept=GTK_RESPONSE_ACCEPT;
    
    GtkWidget *dialog;
    dialog=gtk_file_chooser_dialog_new("Open PCAP File",parentWindow,actionOpen,"Cancel",respCancel,"Open",respAccept,NULL);
    
    GtkDialog *castDialog;
    castDialog=GTK_DIALOG(dialog);
    
    int response;
    response=gtk_dialog_run(castDialog);
    
    if(response==respAccept)
    {
        GtkFileChooser *chooser;
        chooser=GTK_FILE_CHOOSER(dialog);
        
        char *filename;
        filename=gtk_file_chooser_get_filename(chooser);
        
        char *cmdArray[4];
        cmdArray[0]="./PackAnalyzer";
        cmdArray[1]="-F";
        cmdArray[2]=filename;
        cmdArray[3]=NULL;
        
        run_capture(cmdArray);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

void stop_capture(GtkWidget *widget,gpointer data)
{
    if(process_running!=0)
    {
        int signalInt;
        signalInt=SIGINT;
        kill(child_pid,signalInt);
        process_running=0;
    }
    
    char *killCmd;
    killCmd="killall -9 hping3 > /dev/null 2>&1";
    system(killCmd);
    
    gboolean stateFalse;
    stateFalse=FALSE;
    gboolean stateTrue;
    stateTrue=TRUE;
    
    gtk_widget_set_sensitive(btn_start,stateTrue);
    gtk_widget_set_sensitive(btn_open,stateTrue);
    gtk_widget_set_sensitive(btn_stop,stateFalse);
}

void analyze_ip(GtkWidget *widget,gpointer data)
{
    GtkEntry *castEntry;
    castEntry=GTK_ENTRY(analyze_entry);
    
    const gchar *target_ip;
    target_ip=gtk_entry_get_text(castEntry);
    
    int ipLength;
    ipLength=strlen(target_ip);
    
    if(ipLength==0)
    {
        return;
    }
    
    GtkTreeModel *treeModel;
    treeModel=GTK_TREE_MODEL(liststore);
    
    GtkTreeIter iter;
    gboolean valid;
    valid=gtk_tree_model_get_iter_first(treeModel,&iter);
    
    int packetCount;
    packetCount=0;
    
    int endMarker;
    endMarker=-1;
    
    char *detailsBuffer = (char*)malloc(300000);
    if(detailsBuffer == NULL) return;
    detailsBuffer[0]='\0';
    int current_len = 0;
    
    while(valid!=0)
    {
        gchar *dst;
        gchar *proto;
        gchar *len;
        gchar *info;
        
        gtk_tree_model_get(treeModel,&iter,COL_DST,&dst,COL_PROTO,&proto,COL_LEN,&len,COL_INFO,&info,endMarker);
        
        int matchCheck;
        matchCheck=strcmp(dst,target_ip);
        
        if(matchCheck==0)
        {
            packetCount++;
            
            char lineBuf[2000];
            char *formatStr;
            formatStr="[%s] Len: %s bytes | Info: %s\n------------------------------------------------------------\n";
            sprintf(lineBuf,formatStr,proto,len,info);
            
            int addLen = strlen(lineBuf);
            if(current_len+addLen<299000)
            {
                strcpy(detailsBuffer + current_len, lineBuf);
                current_len += addLen;
            }
        }
        
        g_free(dst);
        g_free(proto);
        g_free(len);
        g_free(info);
        
        valid=gtk_tree_model_iter_next(treeModel,&iter);
    }
    
    GtkWidget *resWin;
    GtkWindowType winTop;
    winTop=GTK_WINDOW_TOPLEVEL;
    resWin=gtk_window_new(winTop);
    
    GtkWindow *castResWin;
    castResWin=GTK_WINDOW(resWin);
    
    char titleBuf[500];
    char *titleFormat;
    titleFormat="Analysis Report for %s";
    sprintf(titleBuf,titleFormat,target_ip);
    
    gtk_window_set_title(castResWin,titleBuf);
    
    int winW;
    winW=650;
    int winH;
    winH=500;
    gtk_window_set_default_size(castResWin,winW,winH);
    
    GtkOrientation orientVert;
    orientVert=GTK_ORIENTATION_VERTICAL;
    int spacingFive;
    spacingFive=5;
    
    GtkWidget *vbox;
    vbox=gtk_box_new(orientVert,spacingFive);
    
    GtkContainer *castWinCont;
    castWinCont=GTK_CONTAINER(resWin);
    gtk_container_add(castWinCont,vbox);
    
    char headerText[1000];
    if(packetCount>0)
    {
        char *successFmt;
        successFmt="SUCCESS: IP was accessed!\nTotal Packets Exchanged: %d";
        sprintf(headerText,successFmt,packetCount);
    }
    else
    {
        char *errorFmt;
        errorFmt="ERROR: IP %s was NOT accessed in this session.";
        sprintf(headerText,errorFmt,target_ip);
    }
    
    GtkWidget *headerLabel;
    headerLabel=gtk_label_new(headerText);
    
    GtkBox *castVbox;
    castVbox=GTK_BOX(vbox);
    
    gboolean expandFalse;
    expandFalse=FALSE;
    gboolean fillFalse;
    fillFalse=FALSE;
    guint paddingTen;
    paddingTen=10;
    
    gtk_box_pack_start(castVbox,headerLabel,expandFalse,fillFalse,paddingTen);
    
    GtkWidget *scrollArea;
    scrollArea=gtk_scrolled_window_new(NULL,NULL);
    
    gboolean expandTrue;
    expandTrue=TRUE;
    gboolean fillTrue;
    fillTrue=TRUE;
    
    gtk_box_pack_start(castVbox,scrollArea,expandTrue,fillTrue,paddingTen);
    
    GtkWidget *txtView;
    txtView=gtk_text_view_new();
    
    GtkTextView *castTxtView;
    castTxtView=GTK_TEXT_VIEW(txtView);
    gtk_text_view_set_editable(castTxtView,expandFalse);
    
    GtkTextBuffer *tBuf;
    tBuf=gtk_text_view_get_buffer(castTxtView);
    gtk_text_buffer_set_text(tBuf,detailsBuffer,endMarker);
    
    GtkContainer *castScrollCont;
    castScrollCont=GTK_CONTAINER(scrollArea);
    gtk_container_add(castScrollCont,txtView);
    
    GtkWidget *okBtn;
    char *okLabel;
    okLabel="Close Report";
    okBtn=gtk_button_new_with_label(okLabel);
    
    char *clickedSig;
    clickedSig="clicked";
    g_signal_connect(okBtn,clickedSig,G_CALLBACK(close_window_callback),resWin);
    
    gtk_box_pack_start(castVbox,okBtn,expandFalse,fillFalse,paddingTen);
    
    gtk_widget_show_all(resWin);
    free(detailsBuffer);
}

void check_syn_flood(GtkWidget *widget,gpointer data)
{
    GtkTreeModel *treeModel;
    treeModel=GTK_TREE_MODEL(liststore);
    
    GtkTreeIter iter;
    gboolean valid;
    valid=gtk_tree_model_get_iter_first(treeModel,&iter);
    
    char ipList[1000][50];
    int synList[1000];
    int ackList[1000];
    int totalUnique;
    totalUnique=0;
    
    int endMarker;
    endMarker=-1;
    
    while(valid!=0)
    {
        gchar *info;
        gchar *src;
        gtk_tree_model_get(treeModel,&iter,COL_INFO,&info,COL_SRC,&src,endMarker);
        
        char *synTag;
        synTag="[SYN]";
        
        char *ackTag;
        ackTag="[ACK]";
        
        char *findSyn;
        findSyn=strstr(info,synTag);
        
        char *findAck;
        findAck=strstr(info,ackTag);
        
        int isSYN;
        isSYN=0;
        
        int isACK;
        isACK=0;
        
        if(findSyn!=NULL)
        {
            if(findAck==NULL)
            {
                isSYN=1;
            }
        }
        
        if(findAck!=NULL)
        {
            if(findSyn==NULL)
            {
                isACK=1;
            }
        }
        
        if(isSYN!=0 || isACK!=0)
        {
            int foundIndex;
            foundIndex=-1;
            
            int i;
            for(i=0;i<totalUnique;i++)
            {
                int matchCheck;
                matchCheck=strcmp(ipList[i],src);
                if(matchCheck==0)
                {
                    foundIndex=i;
                    break;
                }
            }
            
            if(foundIndex==-1)
            {
                strcpy(ipList[totalUnique],src);
                synList[totalUnique]=0;
                ackList[totalUnique]=0;
                foundIndex=totalUnique;
                totalUnique++;
            }
            
            if(isSYN!=0)
            {
                synList[foundIndex]++;
            }
            
            if(isACK!=0)
            {
                ackList[foundIndex]++;
            }
        }
        
        g_free(info);
        g_free(src);
        valid=gtk_tree_model_iter_next(treeModel,&iter);
    }
    
    GtkWidget *repWin;
    GtkWindowType winTop;
    winTop=GTK_WINDOW_TOPLEVEL;
    repWin=gtk_window_new(winTop);
    
    GtkWindow *castRepWin;
    castRepWin=GTK_WINDOW(repWin);
    
    char *repTitle;
    repTitle="🛡️ SYN Flood Security Report";
    gtk_window_set_title(castRepWin,repTitle);
    
    int repW;
    repW=700;
    int repH;
    repH=450;
    gtk_window_set_default_size(castRepWin,repW,repH);
    
    GtkOrientation orientVert;
    orientVert=GTK_ORIENTATION_VERTICAL;
    int spacingFive;
    spacingFive=5;
    
    GtkWidget *vbox;
    vbox=gtk_box_new(orientVert,spacingFive);
    
    GtkContainer *castWinCont;
    castWinCont=GTK_CONTAINER(repWin);
    gtk_container_add(castWinCont,vbox);
    
    int step;
    for(step=0;step<totalUnique-1;step++)
    {
        int j;
        for(j=0;j<totalUnique-step-1;j++)
        {
            int halfOpen1;
            halfOpen1=synList[j]-ackList[j];
            
            int halfOpen2;
            halfOpen2=synList[j+1]-ackList[j+1];
            
            if(halfOpen1<halfOpen2)
            {
                int tempSyn;
                tempSyn=synList[j];
                synList[j]=synList[j+1];
                synList[j+1]=tempSyn;
                
                int tempAck;
                tempAck=ackList[j];
                ackList[j]=ackList[j+1];
                ackList[j+1]=tempAck;
                
                char tempIp[50];
                strcpy(tempIp,ipList[j]);
                strcpy(ipList[j],ipList[j+1]);
                strcpy(ipList[j+1],tempIp);
            }
        }
    }
    
    char bannerText[1000];
    
    int maxHalfOpen;
    maxHalfOpen=0;
    
    if(totalUnique>0)
    {
        maxHalfOpen=synList[0]-ackList[0];
    }
    
    if(totalUnique>0 && maxHalfOpen>gui_syn_threshold)
    {
        char *warnMsg;
        warnMsg="⚠️ WARNING: SYN FLOOD ATTACK DETECTED!";
        strcpy(bannerText,warnMsg);
    }
    else
    {
        char *secMsg;
        secMsg="✅ SYSTEM SECURE: TRAFFIC IS NORMAL";
        strcpy(bannerText,secMsg);
    }
    
    GtkWidget *bannerLabel;
    bannerLabel=gtk_label_new(bannerText);
    
    GtkBox *castVbox;
    castVbox=GTK_BOX(vbox);
    
    gboolean expandFalse;
    expandFalse=FALSE;
    gboolean fillFalse;
    fillFalse=FALSE;
    guint paddingTen;
    paddingTen=10;
    
    gtk_box_pack_start(castVbox,bannerLabel,expandFalse,fillFalse,paddingTen);
    
    GtkWidget *scrollArea;
    scrollArea=gtk_scrolled_window_new(NULL,NULL);
    
    gboolean expandTrue;
    expandTrue=TRUE;
    gboolean fillTrue;
    fillTrue=TRUE;
    
    gtk_box_pack_start(castVbox,scrollArea,expandTrue,fillTrue,paddingTen);
    
    GType strType;
    strType=G_TYPE_STRING;
    
    GtkListStore *synStore;
    synStore=gtk_list_store_new(4,strType,strType,strType,strType);
    
    GtkTreeModel *castSynStore;
    castSynStore=GTK_TREE_MODEL(synStore);
    
    GtkWidget *synTree;
    synTree=gtk_tree_view_new_with_model(castSynStore);
    
    GtkCellRenderer *renderer;
    renderer=gtk_cell_renderer_text_new();
    
    GtkTreeView *castSynTree;
    castSynTree=GTK_TREE_VIEW(synTree);
    
    int appendCol;
    appendCol=-1;
    
    char *attrName;
    attrName="text";
    
    gtk_tree_view_insert_column_with_attributes(castSynTree,appendCol,"IP Address",renderer,attrName,0,NULL);
    gtk_tree_view_insert_column_with_attributes(castSynTree,appendCol,"Total SYN",renderer,attrName,1,NULL);
    gtk_tree_view_insert_column_with_attributes(castSynTree,appendCol,"Half-Open",renderer,attrName,2,NULL);
    gtk_tree_view_insert_column_with_attributes(castSynTree,appendCol,"Status",renderer,attrName,3,NULL);
    
    int k;
    for(k=0;k<totalUnique;k++)
    {
        char totalSynStr[20];
        char *fmtInt;
        fmtInt="%d";
        sprintf(totalSynStr,fmtInt,synList[k]);
        
        int halfOpenCalc;
        halfOpenCalc=synList[k]-ackList[k];
        
        if(halfOpenCalc<0)
        {
            halfOpenCalc=0;
        }
        
        char halfOpenStr[20];
        sprintf(halfOpenStr,fmtInt,halfOpenCalc);
        
        char *statusStr;
        if(halfOpenCalc>gui_syn_threshold)
        {
            statusStr="⚠️ ATTACK!";
        }
        else
        {
            statusStr="Normal";
        }
        
        GtkTreeIter iterSyn;
        gtk_list_store_append(synStore,&iterSyn);
        gtk_list_store_set(synStore,&iterSyn,0,ipList[k],1,totalSynStr,2,halfOpenStr,3,statusStr,endMarker);
    }
    
    if(totalUnique==0)
    {
        GtkTreeIter iterSyn;
        gtk_list_store_append(synStore,&iterSyn);
        
        char *naStr;
        naStr="N/A";
        char *zeroStr;
        zeroStr="0";
        char *safeStr;
        safeStr="Safe";
        
        gtk_list_store_set(synStore,&iterSyn,0,naStr,1,zeroStr,2,zeroStr,3,safeStr,endMarker);
    }
    
    GtkContainer *castScrollCont;
    castScrollCont=GTK_CONTAINER(scrollArea);
    gtk_container_add(castScrollCont,synTree);
    
    GtkWidget *okBtn;
    char *okLabel;
    okLabel="Close Report";
    okBtn=gtk_button_new_with_label(okLabel);
    
    char *clickedSig;
    clickedSig="clicked";
    g_signal_connect(okBtn,clickedSig,G_CALLBACK(close_window_callback),repWin);
    
    gtk_box_pack_start(castVbox,okBtn,expandFalse,fillFalse,paddingTen);
    
    gtk_widget_show_all(repWin);
}

int main(int argc,char *argv[])
{
    gtk_init(&argc,&argv);
    process_running=0;
    
    apply_custom_theme();
    
    GtkWindowType winType;
    winType=GTK_WINDOW_TOPLEVEL;
    window=gtk_window_new(winType);
    
    GtkWindow *castWin;
    castWin=GTK_WINDOW(window);
    
    char *appTitle;
    appTitle="PackAnalyzer - Advanced Network Analyzer";
    gtk_window_set_title(castWin,appTitle);
    
    int winWidth;
    winWidth=1200;
    int winHeight;
    winHeight=800;
    gtk_window_set_default_size(castWin,winWidth,winHeight);
    
    g_signal_connect(window,"destroy",G_CALLBACK(gtk_main_quit),NULL);
    
    GtkOrientation orientVert;
    orientVert=GTK_ORIENTATION_VERTICAL;
    int spacingZero;
    spacingZero=0;
    
    GtkWidget *vbox;
    vbox=gtk_box_new(orientVert,spacingZero);
    
    GtkContainer *castContainerWin;
    castContainerWin=GTK_CONTAINER(window);
    gtk_container_add(castContainerWin,vbox);
    
    GtkOrientation orientHorz;
    orientHorz=GTK_ORIENTATION_HORIZONTAL;
    int spacingFive;
    spacingFive=5;
    
    GtkWidget *top_box;
    top_box=gtk_box_new(orientHorz,spacingFive);
    
    GtkBox *castVbox;
    castVbox=GTK_BOX(vbox);
    
    gboolean expandFalse;
    expandFalse=FALSE;
    gboolean fillFalse;
    fillFalse=FALSE;
    guint paddingTen;
    paddingTen=10;
    
    gtk_box_pack_start(castVbox,top_box,expandFalse,fillFalse,paddingTen);
    
    GtkWidget *labelFilter;
    char *filterText;
    filterText="🔍 Filter:";
    labelFilter=gtk_label_new(filterText);
    
    GtkBox *castTopBox;
    castTopBox=GTK_BOX(top_box);
    guint paddingFive;
    paddingFive=5;
    
    gtk_box_pack_start(castTopBox,labelFilter,expandFalse,fillFalse,paddingFive);
    
    search_entry=gtk_entry_new();
    gtk_box_pack_start(castTopBox,search_entry,expandFalse,fillFalse,paddingFive);
    
    char *changedSignal;
    changedSignal="changed";
    g_signal_connect(search_entry,changedSignal,G_CALLBACK(on_search_changed),NULL);
    
    char *liveText;
    liveText="▶ Live";
    btn_start=gtk_button_new_with_label(liveText);
    g_signal_connect(btn_start,"clicked",G_CALLBACK(start_live_capture),NULL);
    gtk_box_pack_start(castTopBox,btn_start,expandFalse,fillFalse,paddingFive);
    
    char *openText;
    openText="📂 Open PCAP";
    btn_open=gtk_button_new_with_label(openText);
    g_signal_connect(btn_open,"clicked",G_CALLBACK(open_pcap_file),NULL);
    gtk_box_pack_start(castTopBox,btn_open,expandFalse,fillFalse,paddingFive);
    
    char *stopText;
    stopText="⏹ Stop";
    btn_stop=gtk_button_new_with_label(stopText);
    
    gboolean stateFalse;
    stateFalse=FALSE;
    gtk_widget_set_sensitive(btn_stop,stateFalse);
    g_signal_connect(btn_stop,"clicked",G_CALLBACK(stop_capture),NULL);
    gtk_box_pack_start(castTopBox,btn_stop,expandFalse,fillFalse,paddingFive);
    
    char *analyzeTextLabel;
    analyzeTextLabel="🌐 Analyzer (IP):";
    GtkWidget *labelAnalyze;
    labelAnalyze=gtk_label_new(analyzeTextLabel);
    
    guint paddingFifteen;
    paddingFifteen=15;
    gtk_box_pack_start(castTopBox,labelAnalyze,expandFalse,fillFalse,paddingFifteen);
    
    analyze_entry=gtk_entry_new();
    gtk_box_pack_start(castTopBox,analyze_entry,expandFalse,fillFalse,paddingFive);
    
    g_signal_connect(analyze_entry,changedSignal,G_CALLBACK(on_search_changed),NULL);
    
    char *analyzeBtnText;
    analyzeBtnText="🔍 Analyze";
    GtkWidget *btn_analyze;
    btn_analyze=gtk_button_new_with_label(analyzeBtnText);
    g_signal_connect(btn_analyze,"clicked",G_CALLBACK(analyze_ip),NULL);
    gtk_box_pack_start(castTopBox,btn_analyze,expandFalse,fillFalse,paddingFive);
    
    char *synBtnText;
    synBtnText="🛡️ SYN Check";
    GtkWidget *btn_syn;
    btn_syn=gtk_button_new_with_label(synBtnText);
    g_signal_connect(btn_syn,"clicked",G_CALLBACK(check_syn_flood),NULL);
    gtk_box_pack_start(castTopBox,btn_syn,expandFalse,fillFalse,paddingFifteen);
    
    // ২য় টুলবার (Attack)
    GtkWidget *toolbar2;
    toolbar2=gtk_box_new(orientHorz,spacingFive);
    gtk_box_pack_start(castVbox,toolbar2,expandFalse,fillFalse,paddingTen);
    
    char *attackLabelTxt;
    attackLabelTxt="🎯 Attack Target (IP):";
    GtkWidget *labelAttack;
    labelAttack=gtk_label_new(attackLabelTxt);
    
    GtkBox *castToolbar2;
    castToolbar2=GTK_BOX(toolbar2);
    gtk_box_pack_start(castToolbar2,labelAttack,expandFalse,fillFalse,paddingFive);
    
    attack_entry=gtk_entry_new();
    gtk_box_pack_start(castToolbar2,attack_entry,expandFalse,fillFalse,paddingFive);
    
    char *attackBtnTxt;
    attackBtnTxt="🔥 Launch Attack";
    btn_attack=gtk_button_new_with_label(attackBtnTxt);
    char *clickedStr;
    clickedStr="clicked";
    g_signal_connect(btn_attack,clickedStr,G_CALLBACK(launch_attack),NULL);
    gtk_box_pack_start(castToolbar2,btn_attack,expandFalse,fillFalse,paddingFive);
    
    char *stopAttackBtnTxt;
    stopAttackBtnTxt="🛑 Stop Attack";
    btn_stop_attack=gtk_button_new_with_label(stopAttackBtnTxt);
    g_signal_connect(btn_stop_attack,clickedStr,G_CALLBACK(stop_attack),NULL);
    gtk_box_pack_start(castToolbar2,btn_stop_attack,expandFalse,fillFalse,paddingFive);
    
    // ৩য় টুলবার (নতুন: Domain History Search)
    GtkWidget *toolbar3;
    toolbar3=gtk_box_new(orientHorz,spacingFive);
    gtk_box_pack_start(castVbox,toolbar3,expandFalse,fillFalse,paddingTen);
    
    char *domLabelTxt;
    domLabelTxt="🌍 Search Visited Domain (ex: youtube):";
    GtkWidget *labelDomain;
    labelDomain=gtk_label_new(domLabelTxt);
    
    GtkBox *castToolbar3;
    castToolbar3=GTK_BOX(toolbar3);
    gtk_box_pack_start(castToolbar3,labelDomain,expandFalse,fillFalse,paddingFive);
    
    domain_entry=gtk_entry_new();
    gtk_box_pack_start(castToolbar3,domain_entry,expandFalse,fillFalse,paddingFive);
    
    char *domBtnTxt;
    domBtnTxt="🔍 Check History";
    GtkWidget *btn_domain;
    btn_domain=gtk_button_new_with_label(domBtnTxt);
    g_signal_connect(btn_domain,clickedStr,G_CALLBACK(search_domain),NULL);
    gtk_box_pack_start(castToolbar3,btn_domain,expandFalse,fillFalse,paddingFive);
    
    GtkWidget *paned;
    paned=gtk_paned_new(orientVert);
    
    gboolean expandTrue;
    expandTrue=TRUE;
    gboolean fillTrue;
    fillTrue=TRUE;
    
    gtk_box_pack_start(castVbox,paned,expandTrue,fillTrue,paddingFive);
    
    GtkWidget *scroll_tree;
    scroll_tree=gtk_scrolled_window_new(NULL,NULL);
    
    GtkPaned *castPaned;
    castPaned=GTK_PANED(paned);
    gtk_paned_pack1(castPaned,scroll_tree,expandTrue,fillFalse);
    
    GType strType;
    strType=G_TYPE_STRING;
    liststore=gtk_list_store_new(NUM_COLS,strType,strType,strType,strType,strType,strType,strType,strType,strType,strType,strType);
    
    GtkTreeModel *castListStore;
    castListStore=GTK_TREE_MODEL(liststore);
    
    filter_model=gtk_tree_model_filter_new(castListStore,NULL);
    
    GtkTreeModelFilter *castFilterModel;
    castFilterModel=GTK_TREE_MODEL_FILTER(filter_model);
    
    GtkTreeModelFilterVisibleFunc visFunc;
    visFunc=(GtkTreeModelFilterVisibleFunc)filter_vis_func;
    
    gtk_tree_model_filter_set_visible_func(castFilterModel,visFunc,NULL,NULL);
    
    treeview=gtk_tree_view_new_with_model(filter_model);
    
    GtkCellRenderer *renderer;
    renderer=gtk_cell_renderer_text_new();
    
    GtkTreeView *castTreeView;
    castTreeView=GTK_TREE_VIEW(treeview);
    
    int appendCol;
    appendCol=-1;
    
    char *attrName;
    attrName="text";
    
    gtk_tree_view_insert_column_with_attributes(castTreeView,appendCol,"No.",renderer,attrName,COL_NO,NULL);
    gtk_tree_view_insert_column_with_attributes(castTreeView,appendCol,"Time",renderer,attrName,COL_TIME,NULL);
    gtk_tree_view_insert_column_with_attributes(castTreeView,appendCol,"Source",renderer,attrName,COL_SRC,NULL);
    gtk_tree_view_insert_column_with_attributes(castTreeView,appendCol,"Destination",renderer,attrName,COL_DST,NULL);
    gtk_tree_view_insert_column_with_attributes(castTreeView,appendCol,"Protocol",renderer,attrName,COL_PROTO,NULL);
    gtk_tree_view_insert_column_with_attributes(castTreeView,appendCol,"Length",renderer,attrName,COL_LEN,NULL);
    gtk_tree_view_insert_column_with_attributes(castTreeView,appendCol,"Info",renderer,attrName,COL_INFO,NULL);
    
    GtkTreeSelection *selection;
    selection=gtk_tree_view_get_selection(castTreeView);
    g_signal_connect(selection,"changed",G_CALLBACK(on_row_selected),NULL);
    
    GtkContainer *castScrollTree;
    castScrollTree=GTK_CONTAINER(scroll_tree);
    gtk_container_add(castScrollTree,treeview);
    
    GtkWidget *scroll_text;
    scroll_text=gtk_scrolled_window_new(NULL,NULL);
    gtk_paned_pack2(castPaned,scroll_text,expandTrue,fillFalse);
    
    detail_area=gtk_text_view_new();
    
    GtkTextView *castDetailArea;
    castDetailArea=GTK_TEXT_VIEW(detail_area);
    gtk_text_view_set_editable(castDetailArea,stateFalse);
    
    text_buffer=gtk_text_view_get_buffer(castDetailArea);
    
    GtkContainer *castScrollText;
    castScrollText=GTK_CONTAINER(scroll_text);
    gtk_container_add(castScrollText,detail_area);
    
    gtk_widget_show_all(window);
    gtk_main();
    
    return 0;
}