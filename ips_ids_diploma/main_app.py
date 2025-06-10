import customtkinter as ctk
from tkinter import ttk, messagebox, END as TK_END
import datetime
import json
from scapy.all import sniff
from scapy.arch.windows import get_windows_if_list
import threading
import os
import platform
import socket

from firewall_manager import block_ip
import config
import data_handlers
import sniffer_logic
import ai_analyzer


class SimpleIDS_IPS_App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Simple IDS/IPS (Corrected Structure)")
        self.geometry("1450x850")
        self.current_theme_mode = ctk.get_appearance_mode()
        self.widget_bg_color = None
        self.text_color = None
        self.selected_row_color = None
        self.header_bg_color = None
        self.bad_ips_info = {}
        self.bad_domains_info = {}
        self.sniffing_thread = None
        self.stop_sniffing_event = threading.Event()
        self.selected_interface_name = None
        self.aggregated_event_id_counter = 0
        self.live_aggregated_threats = {}

        self.all_threat_data_history = []
        self.threat_details_json = {}
        self.update_colors_from_theme()
        self._create_gui_elements()

        loaded_ips_info, loaded_domains_info, feed_log_messages = data_handlers.load_all_feeds_data()
        self.bad_ips_info = loaded_ips_info
        self.bad_domains_info = loaded_domains_info
        for msg in feed_log_messages: self._log_message_app_event(msg)

        session_data, session_log_msgs = data_handlers.load_session_state_from_file()
        for msg in session_log_msgs: self._log_message_app_event(msg)

        if session_data:
            self.all_threat_data_history = session_data.get("all_threat_data", [])
            self.threat_details_json = session_data.get("threat_details_json", {})

        if self.all_threat_data_history:
            self.populate_table_with_history()
            all_iids_in_table = self.threat_table.get_children()
            if all_iids_in_table:
                first_iid_to_select = all_iids_in_table[0]
                try:
                    if self.threat_table.exists(first_iid_to_select):
                        self.threat_table.selection_set(first_iid_to_select)
                        self.threat_table.focus(first_iid_to_select)
                        self.threat_table.see(first_iid_to_select)
                        if hasattr(self, 'on_threat_select'): self.on_threat_select(None)
                except Exception as e_select:
                    self._log_message_app_event(f"WARNING: Помилка при виборі першого елемента: {e_select}")
        else:
            self.apply_filter()


    def update_colors_from_theme(self):
        if self.current_theme_mode == "Dark":
            self.widget_bg_color = config.DARK_WIDGET_BG
            self.text_color = config.DARK_TEXT
            self.selected_row_color = config.DARK_SELECTED_ROW
            self.header_bg_color = config.DARK_HEADER_BG
        else:
            self.widget_bg_color = config.LIGHT_WIDGET_BG
            self.text_color = config.LIGHT_TEXT
            self.selected_row_color = config.LIGHT_SELECTED_ROW
            self.header_bg_color = config.LIGHT_HEADER_BG

        if hasattr(self, 'log_text') and self.log_text:
            self.log_text.configure(fg_color=self.widget_bg_color, text_color=self.text_color)
        if hasattr(self, 'packet_details_text') and self.packet_details_text:
            self.packet_details_text.configure(fg_color=self.widget_bg_color, text_color=self.text_color)
        if hasattr(self, 'ai_analysis_text') and self.ai_analysis_text:
            self.ai_analysis_text.configure(fg_color=self.widget_bg_color, text_color=self.text_color)
        if hasattr(self, 'threat_table') and self.threat_table:
            self._setup_treeview_style()

    def populate_table_with_history(self):
        if not hasattr(self, 'threat_table'): return
        for iid, data_tuple, _ in self.all_threat_data_history:
            adapted_data_tuple = data_tuple
            if len(data_tuple) == len(config.THREAT_TABLE_COLS_INTERNAL) - 1:
                adapted_data_tuple = (
                    data_tuple[0], 1, data_tuple[1], data_tuple[2], data_tuple[3], data_tuple[4],
                    data_tuple[5], data_tuple[6], data_tuple[7], data_tuple[8], data_tuple[9], data_tuple[10]
                )
            elif len(data_tuple) != len(config.THREAT_TABLE_COLS_INTERNAL):
                self._log_message_app_event(f"WARNING: Некоректний кортеж для історії ID {iid}, пропущено.")
                continue

            if not self.threat_table.exists(iid):
                self.threat_table.insert("", "end", iid=iid, values=adapted_data_tuple)

    def _create_gui_elements(self):
        self.main_frame = ctk.CTkFrame(self); self.main_frame.pack(pady=10, padx=10, fill="both", expand=True)
        self.top_controls_frame = ctk.CTkFrame(self.main_frame); self.top_controls_frame.pack(pady=(0, 5), padx=5, fill="x")
        self.interface_label = ctk.CTkLabel(self.top_controls_frame, text="Інтерфейс:"); self.interface_label.pack(side="left", padx=(0, 5))
        try:
            self.interfaces_details = get_windows_if_list(); self.interface_names = [i['name'] for i in self.interfaces_details if i.get('name')]
        except Exception as e: self.after(10, lambda: self._log_message_app_event(f"ERROR: Помилка отримання списку інтерфейсів: {e}. Можливо, Npcap не встановлено.")); self.interfaces_details,self.interface_names = [],[]
        initial_interface = self.interface_names[0] if self.interface_names else "Немає інтерфейсів"
        self.interface_var = ctk.StringVar(value=initial_interface)
        self.interface_menu = ctk.CTkOptionMenu(self.top_controls_frame, variable=self.interface_var, values=self.interface_names if self.interface_names else ["Немає інтерфейсів"])
        if not self.interface_names: self.interface_menu.configure(state="disabled")
        self.interface_menu.pack(side="left", padx=5)
        self.start_button = ctk.CTkButton(self.top_controls_frame, text="Почати", command=lambda: self.start_sniffing(), width=100)
        if not self.interface_names: self.start_button.configure(state="disabled")
        self.start_button.pack(side="left", padx=(10, 5))
        self.stop_button = ctk.CTkButton(self.top_controls_frame, text="Зупинити", command=lambda: self.stop_sniffing(), state="disabled", width=100)
        self.stop_button.pack(side="left", padx=5)
        self.update_feeds_button = ctk.CTkButton(self.top_controls_frame, text="Оновити Фіди", command=lambda: self.trigger_feed_update(), width=120)
        self.update_feeds_button.pack(side="left", padx=15)
        self.history_filter_panel = ctk.CTkFrame(self.main_frame); self.history_filter_panel.pack(pady=5, padx=5, fill="x")
        self.date_label = ctk.CTkLabel(self.history_filter_panel, text="Дата історії (РРРР-ММ-ДД):"); self.date_label.pack(side="left", padx=(0, 5))
        self.history_date_entry_var = ctk.StringVar(value=datetime.date.today().strftime("%Y-%m-%d"))
        self.history_date_entry = ctk.CTkEntry(self.history_filter_panel, textvariable=self.history_date_entry_var, width=120); self.history_date_entry.pack(side="left", padx=5)
        self.load_history_button = ctk.CTkButton(self.history_filter_panel, text="Завантажити історію", command=lambda: self.load_history_for_date(), width=150); self.load_history_button.pack(side="left", padx=5)
        ctk.CTkLabel(self.history_filter_panel, text="     ").pack(side="left")
        self.filter_label = ctk.CTkLabel(self.history_filter_panel, text="Фільтр:"); self.filter_label.pack(side="left", padx=(0, 5))
        self.filter_entry_var = ctk.StringVar(); self.filter_entry_var.trace_add("write", self.apply_filter)
        self.filter_entry = ctk.CTkEntry(self.history_filter_panel, textvariable=self.filter_entry_var); self.filter_entry.pack(side="left", padx=5, fill="x", expand=True)
        self.clear_filter_button = ctk.CTkButton(self.history_filter_panel, text="Очистити", command=lambda: self.clear_filter(), width=100); self.clear_filter_button.pack(side="left", padx=5)
        self.center_panel = ctk.CTkFrame(self.main_frame, fg_color="transparent"); self.center_panel.pack(pady=5, padx=5, fill="both", expand=True)
        self.center_panel.grid_columnconfigure(0, weight=3); self.center_panel.grid_columnconfigure(1, weight=0); self.center_panel.grid_columnconfigure(2, weight=2); self.center_panel.grid_rowconfigure(0, weight=1)
        self.tree_container_frame = ctk.CTkFrame(self.center_panel, fg_color="transparent"); self.tree_container_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5)); self.tree_container_frame.grid_rowconfigure(0, weight=1); self.tree_container_frame.grid_columnconfigure(0, weight=1)
        self.threat_table = ttk.Treeview(self.tree_container_frame, columns=config.THREAT_TABLE_COLS_INTERNAL, show="headings", style="Treeview")
        for internal_name in config.THREAT_TABLE_COLS_INTERNAL:
            display_name = config.THREAT_TABLE_COLS_DISPLAY[internal_name]
            self.threat_table.heading(internal_name, text=display_name)
            self.threat_table.column(internal_name, width=config.COL_WIDTHS.get(internal_name, 100), anchor=config.COL_ALIGN.get(internal_name, "w"), minwidth=40)
        self.vsb = ttk.Scrollbar(self.tree_container_frame, orient="vertical", command=self.threat_table.yview); self.hsb = ttk.Scrollbar(self.tree_container_frame, orient="horizontal", command=self.threat_table.xview)
        self.threat_table.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        self.threat_table.grid(row=0, column=0, sticky="nsew"); self.vsb.grid(row=0, column=1, sticky="ns"); self.hsb.grid(row=1, column=0, sticky="ew")
        self.threat_table.bind("<<TreeviewSelect>>", self.on_threat_select)
        self.threat_table.bind("<Double-1>", self.on_cell_double_click_for_filter)
        self._setup_treeview_style()
        self.separator_frame = ctk.CTkFrame(self.center_panel, width=2, fg_color="gray50"); self.separator_frame.grid(row=0, column=1, sticky='ns', padx=5)
        self.packet_details_panel = ctk.CTkFrame(self.center_panel); self.packet_details_panel.grid(row=0, column=2, sticky="nsew", padx=(5, 0)); self.packet_details_panel.grid_rowconfigure(1, weight=1); self.packet_details_panel.grid_columnconfigure(0, weight=1)
        self.packet_details_label = ctk.CTkLabel(self.packet_details_panel, text="Деталі загрози (JSON):", font=ctk.CTkFont(weight="bold")); self.packet_details_label.grid(row=0, column=0, pady=(0,5), padx=5, sticky="w")
        self.packet_details_text = ctk.CTkTextbox(self.packet_details_panel, wrap="none", state="normal", fg_color=self.widget_bg_color, text_color=self.text_color); self.packet_details_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0,5))
        self.bottom_panel = ctk.CTkFrame(self.main_frame, fg_color="transparent"); self.bottom_panel.pack(pady=(10,0), padx=5, fill="x")
        self.manual_action_button = ctk.CTkButton(self.bottom_panel, text="Блокувати/Інфо (Ручна дія)",command=lambda: self.perform_manual_action_on_selected()); self.manual_action_button.pack(side="left", pady=(5,0), padx=(0,5))
        self.ai_action_button = ctk.CTkButton(self.bottom_panel, text="Аналіз та Авто-Блок (ШІ)", command=lambda: self.perform_ai_action_on_selected()); self.ai_action_button.pack(side="left", pady=(5,0), padx=5)
        self.clear_table_button = ctk.CTkButton(self.bottom_panel, text="Очистити таблицю", command=lambda: self.clear_current_table_view_and_data()); self.clear_table_button.pack(side="left", pady=(5,0), padx=5)
        self.log_label = ctk.CTkLabel(self.main_frame, text="Лог подій програми:", font=ctk.CTkFont(weight="bold")); self.log_label.pack(pady=(10,2), padx=5, anchor="w")
        self.log_text_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent"); self.log_text_frame.pack(pady=(0,5), padx=5, fill="x")
        self.log_text = ctk.CTkTextbox(self.log_text_frame, height=60, fg_color=self.widget_bg_color, text_color=self.text_color, state="disabled"); self.log_text.pack(fill="x", expand=True)

    def perform_manual_action_on_selected(self):
        selected_items = self.threat_table.selection()
        if not selected_items: self._log_message_app_event("WARNING: Не обрано елемента для ручної дії."); return
        selected_iid = selected_items[0]
        json_details_str = self.threat_details_json.get(selected_iid)
        if not json_details_str: self._log_message_app_event(f"ERROR: Немає JSON для ID: {selected_iid}."); return
        try:
            threat_details = json.loads(json_details_str)
            ioc_type, indicator = threat_details.get("ioc_type", "").upper(), threat_details.get("indicator", "")
        except json.JSONDecodeError:
            self._log_message_app_event(f"ERROR: Парсинг JSON для ID: {selected_iid}."); return
        if not ioc_type or not indicator: self._log_message_app_event(
            f"ERROR: 'ioc_type'/'indicator' відсутні для ID: {selected_iid}."); return
        if ioc_type == "IP":
            if messagebox.askyesno("Підтвердження блокування IP", f"Заблокувати IP: {indicator}?"):
                self._block_ip_action(indicator, selected_iid)
            else:
                self._log_message_app_event(f"INFO: Скасовано блокування IP: {indicator}")
        elif ioc_type == "DOMAIN":
            self._handle_domain_action(indicator, selected_iid, manual_confirmation=True)
        else:
            self._log_message_app_event(f"INFO: Для '{ioc_type}' ('{indicator}') ручна дія не визначена.")

    def perform_ai_action_on_selected(self):
        selected_items = self.threat_table.selection()
        if not selected_items: self._log_message_app_event("WARNING: Не обрано елемента для аналізу ШІ."); return
        selected_iid = selected_items[0]
        json_details_str = self.threat_details_json.get(selected_iid)
        if not json_details_str: self._log_message_app_event(
            f"ERROR: Не знайдено JSON деталі для ID: {selected_iid}."); return
        try:
            threat_details = json.loads(json_details_str)
            ioc_type, indicator = threat_details.get("ioc_type", "").upper(), threat_details.get("indicator", "")
        except json.JSONDecodeError:
            self._log_message_app_event(f"ERROR: Не вдалося розпарсити JSON деталі для ID: {selected_iid}."); return
        if not ioc_type or not indicator: self._log_message_app_event(
            f"ERROR: 'ioc_type'/'indicator' відсутні в JSON для ID: {selected_iid}."); return
        self._log_message_app_event(f"INFO: Надсилання індикатора '{indicator}' ({ioc_type}) на аналіз OpenAI API...")
        if hasattr(self, 'ai_action_button'): self.ai_action_button.configure(state="disabled", text="Аналіз ШІ...")
        if hasattr(self, 'manual_action_button'): self.manual_action_button.configure(state="disabled")

        def ai_analysis_task():
            ai_result = data_handlers.analyze_indicator_with_openai(indicator, ioc_type)
            if hasattr(self, 'after'): self.after(0, self.reenable_action_buttons)
            if ai_result.get('error'):
                self._log_message_app_event(f"ERROR (OpenAI): {ai_result['description']}")
                if hasattr(self, 'after'): self.after(0, lambda: messagebox.showerror("Помилка аналізу ШІ",
                                                                                      ai_result['description']))
                return
            self._log_message_app_event(f"INFO (OpenAI для {indicator}): {ai_result['description']}")
            self._log_message_app_event(
                f"INFO (OpenAI Рішення): Блокувати? {'Так' if ai_result['should_block'] else 'Ні'}. Причина: {ai_result['reason']}")
            if hasattr(self, 'packet_details_text'):
                def update_details_panel():
                    current_details = self.packet_details_text.get("1.0", TK_END).strip()
                    try:
                        details_obj = json.loads(current_details)
                    except json.JSONDecodeError:
                        details_obj = {"original_data": current_details}
                    details_obj["ai_analysis"] = {"assessment": ai_result['description'],
                                                  "decision_to_block": ai_result['should_block'],
                                                  "decision_reason": ai_result['reason']}
                    self.packet_details_text.delete("1.0", TK_END);
                    self.packet_details_text.insert("1.0", json.dumps(details_obj, indent=4, ensure_ascii=False))
                    self.threat_details_json[selected_iid] = json.dumps(details_obj, ensure_ascii=False)

                if hasattr(self, 'after'): self.after(0, update_details_panel)
            if ai_result['should_block']:
                self._log_message_app_event(
                    f"INFO: ШІ рекомендував блокування для {indicator} ({ioc_type}). Причина: {ai_result['reason']}. Виконується автоматичне блокування.")
                if ioc_type == "IP":
                    self._block_ip_action(indicator, selected_iid)
                elif ioc_type == "DOMAIN":
                    self._handle_domain_action(indicator, selected_iid, manual_confirmation=False)
            else:
                self._log_message_app_event(
                    f"INFO: ШІ не рекомендував автоматичне блокування для {indicator}. Причина: {ai_result['reason']}.")
                if hasattr(self, 'after'): self.after(0, lambda: messagebox.showinfo("Результат аналізу ШІ",
                                                                                     f"Індикатор: {indicator} ({ioc_type})\n\nОцінка ШІ: {ai_result['description']}\n\nРішення ШІ: Блокувати? {'Так' if ai_result['should_block'] else 'Ні'}\nПричина: {ai_result['reason']}\n\nАвтоматичне блокування не виконано."))

        threading.Thread(target=ai_analysis_task, daemon=True).start()

    def reenable_action_buttons(self):
        if hasattr(self, 'ai_action_button'): self.ai_action_button.configure(state="normal",
                                                                              text="Аналіз та Авто-Блок (ШІ)")
        if hasattr(self, 'manual_action_button'): self.manual_action_button.configure(state="normal")


    def _get_aggregation_key(self, packet_info_dict, indicator_type, indicator_value, alert_metadata):
        key_tuple = (packet_info_dict.get("src_ip", "N/A"), packet_info_dict.get("dst_ip", "N/A"),
                     packet_info_dict.get("protocol", "N/A"), indicator_type, indicator_value,
                     alert_metadata.get('feed_source', 'N/A'),)
        return key_tuple

    def alert_threat(self, packet_info_dict, indicator_type, indicator_value, alert_metadata, packet_summary_str):
        aggregation_key = self._get_aggregation_key(packet_info_dict, indicator_type, indicator_value, alert_metadata);
        current_timestamp = packet_info_dict["timestamp"]
        individual_alert_json_for_log = {"id": f"evt_{datetime.datetime.now().timestamp()}",
                                         "timestamp": current_timestamp,
                                         "severity": alert_metadata.get('severity', 'UNKNOWN'),
                                         "src_ip": packet_info_dict["src_ip"], "src_port": packet_info_dict["src_port"],
                                         "dst_ip": packet_info_dict["dst_ip"], "dst_port": packet_info_dict["dst_port"],
                                         "protocol": packet_info_dict["protocol"], "ioc_type": indicator_type,
                                         "indicator": indicator_value,
                                         "feed_source": alert_metadata.get('source_feed', 'N/A'),
                                         "description": alert_metadata.get('description', 'N/A'),
                                         "reference": alert_metadata.get('reference', '')}
        if not self.stop_sniffing_event.is_set(): log_err_msg = data_handlers.write_alert_to_daily_log(
            individual_alert_json_for_log);
        if log_err_msg: self._log_message_app_event(log_err_msg)
        if aggregation_key in self.live_aggregated_threats:
            agg_data = self.live_aggregated_threats[aggregation_key];
            agg_data['count'] += 1;
            agg_data['last_timestamp'] = current_timestamp;
            agg_data['full_json_details'] = individual_alert_json_for_log;
            agg_data['severity'] = alert_metadata.get('severity', agg_data.get('severity', 'UNKNOWN'));
            agg_data['src_port'] = packet_info_dict.get("src_port", agg_data.get('src_port', 'N/A'));
            agg_data['dst_port'] = packet_info_dict.get("dst_port", agg_data.get('dst_port', 'N/A'))
            updated_display_tuple = (agg_data['table_iid'].split('_')[-1], agg_data['count'],
                                     agg_data['last_timestamp'], agg_data['severity'], packet_info_dict["src_ip"],
                                     agg_data['src_port'], packet_info_dict["dst_ip"], agg_data['dst_port'],
                                     packet_info_dict["protocol"], indicator_type, indicator_value,
                                     alert_metadata.get('source_feed', 'N/A'), alert_metadata.get('description', 'N/A'))
            agg_data['data_for_display'] = updated_display_tuple;
            table_iid_to_update = agg_data['table_iid'];
            self.threat_details_json[table_iid_to_update] = json.dumps(individual_alert_json_for_log,
                                                                       ensure_ascii=False)
            if hasattr(self, 'after'): self.after(0, lambda iid=table_iid_to_update,
                                                            values=updated_display_tuple: self.update_table_row(iid,
                                                                                                                values))
        else:
            self.aggregated_event_id_counter += 1;
            new_table_iid = f"live_agg_{self.aggregated_event_id_counter}"
            display_tuple = (self.aggregated_event_id_counter, 1, current_timestamp,
                             alert_metadata.get('severity', 'UNKNOWN'), packet_info_dict["src_ip"],
                             packet_info_dict["src_port"], packet_info_dict["dst_ip"], packet_info_dict["dst_port"],
                             packet_info_dict["protocol"], indicator_type, indicator_value,
                             alert_metadata.get('source_feed', 'N/A'), alert_metadata.get('description', 'N/A'))
            self.live_aggregated_threats[aggregation_key] = {'count': 1, 'last_timestamp': current_timestamp,
                                                             'table_iid': new_table_iid,
                                                             'severity': alert_metadata.get('severity', 'UNKNOWN'),
                                                             'src_port': packet_info_dict.get("src_port", "N/A"),
                                                             'dst_port': packet_info_dict.get("dst_port", "N/A"),
                                                             'data_for_display': display_tuple,
                                                             'full_json_details': individual_alert_json_for_log}
            self.threat_details_json[new_table_iid] = json.dumps(individual_alert_json_for_log, ensure_ascii=False)
            if hasattr(self, 'after'): self.after(0,
                                                  lambda iid=new_table_iid, values=display_tuple: self.insert_table_row(
                                                      iid, values))

    def update_table_row(self, iid, values):
        if hasattr(self, 'threat_table') and self.threat_table.exists(iid):
            self.threat_table.item(iid, values=values)
        elif hasattr(self, 'threat_table'):
            self.insert_table_row(iid, values)

    def insert_table_row(self, iid, values):
        if not hasattr(self, 'threat_table'): return
        filter_term = self.filter_entry_var.get().lower();
        key, val = None, None
        if ":" in filter_term: p = filter_term.split(":", 1); key = p[0] if p[
                                                                                0] in config.THREAT_TABLE_COLS_INTERNAL else None; val = \
        p[1] if key else None
        match = False
        if not filter_term:
            match = True
        elif key and val is not None:
            try:
                match = val in str(values[config.THREAT_TABLE_COLS_INTERNAL.index(key)]).lower()
            except:
                match = any(filter_term in str(v).lower() for v in values)
        else:
            match = any(filter_term in str(v).lower() for v in values)
        if match:
            if not self.threat_table.exists(iid):
                self.threat_table.insert("", "end", iid=iid, values=values); self.threat_table.see(iid)
            else:
                self.threat_table.item(iid, values=values)

    def on_cell_double_click_for_filter(self, event):
        if not hasattr(self, 'threat_table'): return
        region = self.threat_table.identify_region(event.x, event.y)
        if region == "cell": item, col_id = self.threat_table.identify_row(event.y), self.threat_table.identify_column(
            event.x)
        if item and col_id:
            try:
                idx = int(col_id.replace('#', '')) - 1
                if 0 <= idx < len(config.THREAT_TABLE_COLS_INTERNAL): name, value = config.THREAT_TABLE_COLS_INTERNAL[
                    idx], self.threat_table.set(item, idx)
                if value: self.filter_entry_var.set(f"{name}:{value}");self.filter_entry.icursor(
                    TK_END);self.filter_entry.focus_set()
            except ValueError:
                self._log_message_app_event("WARNING: Помилка визначення колонки.")
            except Exception as e:
                self._log_message_app_event(f"ERROR: Клік на комірку: {e}")

    def perform_action_on_selected(self):
        if not hasattr(self, 'threat_table'): return
        items = self.threat_table.selection();
        if not items: self._log_message_app_event("WARNING: Не обрано елемента.");return
        iid = items[0];
        details_str = self.threat_details_json.get(iid)
        if not details_str: self._log_message_app_event(f"ERROR: Немає JSON для ID: {iid}.");return
        try:
            details = json.loads(details_str);ioc, ind = details.get("ioc_type", "").upper(), details.get("indicator",
                                                                                                          "")
        except json.JSONDecodeError:
            self._log_message_app_event(f"ERROR: Парсинг JSON для ID: {iid}.");return
        if not ioc or not ind: self._log_message_app_event(
            f"ERROR: 'ioc_type'/'indicator' відсутні для ID: {iid}.");return
        if ioc == "IP":
            if messagebox.askyesno("Блокування IP", f"Заблокувати IP: {ind}?"):
                self._block_ip_action(ind, iid)
            else:
                self._log_message_app_event(f"INFO: Скасовано блокування IP: {ind}")
        elif ioc == "DOMAIN":
            self._handle_domain_action(ind, iid)
        elif ioc == "IP_CIDR":
            self._log_message_app_event(f"INFO: Блокування CIDR ('{ind}') не реалізовано.")
        else:
            self._log_message_app_event(f"INFO: Для типу '{ioc}' ('{ind}') дія не визначена.")

    def _block_ip_action(self, ip, iid):
        self._log_message_app_event(f"INFO: Спроба блокування IP: {ip}")
        try:
            parts = ip.split('.');assert len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except:
            self._log_message_app_event(f"ERROR: '{ip}' не IP-адреса.");return
        ok, msg = block_ip(ip)
        if ok:
            self._log_message_app_event(f"INFO: IP {ip} заблоковано."); self.threat_table.item(iid, tags=('blocked',))
        else:
            self._log_message_app_event(f"ERROR: Не вдалося заблокувати {ip}: {msg}")

    def _handle_domain_action(self, domain, iid):
        self._log_message_app_event(f"INFO: Резолвінг домену: {domain}")
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET);
            ips = list(set([i[4][0] for i in info]))
            if not ips: self._log_message_app_event(f"WARNING: Немає IPv4 для {domain}.");messagebox.showinfo(
                "Резолвінг", f"Немає IPv4 для: {domain}");return
            self._log_message_app_event(f"INFO: Домен {domain} -> IP: {', '.join(ips)}")
            for ip_res in ips:
                if messagebox.askyesno("Блокувати IP для домену",
                                       f"Домен '{domain}' -> IP: {ip_res}.\nЗаблокувати {ip_res}?"):
                    self._block_ip_action(ip_res, iid)
                else:
                    self._log_message_app_event(f"INFO: Скасовано блокування IP {ip_res} для {domain}")
            messagebox.showinfo("Блокування домену",
                                f"Для блокування '{domain}', додайте\n'0.0.0.0   {domain}'\nу файл hosts.")
        except socket.gaierror as e:
            self._log_message_app_event(f"ERROR: Резолвінг {domain}: {e}");messagebox.showerror("Помилка",
                                                                                                f"Резолвінг {domain}: {e}")
        except Exception as e_res:
            self._log_message_app_event(f"ERROR: Обробка {domain}: {e_res}");messagebox.showerror("Помилка", f"{e_res}")

    def on_threat_select(self, event):
        if not hasattr(self, 'threat_table') or not hasattr(self, 'packet_details_text') or not hasattr(self,
                                                                                                        'ai_analysis_text'): return
        selected_items = self.threat_table.selection()

        self.ai_analysis_text.delete("1.0", TK_END)
        if hasattr(self, 'analyze_ai_button'): self.analyze_ai_button.configure(state="normal",
                                                                                text="Аналізувати з OpenAI")

        if not selected_items:
            self.packet_details_text.delete("1.0", TK_END)
            return

        selected_iid = selected_items[0];
        json_details_str = None
        if selected_iid.startswith("live_agg_"):
            for data in self.live_aggregated_threats.values():
                if data['table_iid'] == selected_iid:
                    json_details_str = json.dumps(data.get('full_json_details', {}), indent=4, ensure_ascii=False);
                    break
        if not json_details_str: json_details_str = self.threat_details_json.get(selected_iid,
                                                                                 f'{{"error": "ID \'{selected_iid}\' деталі відсутні."}}')

        self.packet_details_text.delete("1.0", TK_END)
        try:
            loaded_json = json.loads(json_details_str)
            formatted_json = json.dumps(loaded_json, indent=4, ensure_ascii=False)
            self.packet_details_text.insert("1.0", formatted_json)
        except json.JSONDecodeError:
            self.packet_details_text.insert("1.0", json_details_str)

    def _setup_treeview_style(self):
        """Налаштовує стиль для віджета ttk.Treeview відповідно до поточної теми."""
        if not hasattr(self, 'threat_table'):
            return

        style = ttk.Style()

        try:
            current_theme = style.theme_use()
            if not current_theme:
                style.theme_use("default")
        except Exception:
            style.theme_use("default")

        style.configure("Treeview",
                        background=self.widget_bg_color,
                        foreground=self.text_color,
                        fieldbackground=self.widget_bg_color,
                        borderwidth=1,
                        relief="solid",
                        rowheight=25)


        style.map('Treeview',
                  background=[('selected', self.selected_row_color)],
                  foreground=[('selected',
                               self.text_color if self.current_theme_mode == "Light" else config.LIGHT_TEXT)])

        style.configure("Treeview.Heading",
                        background=self.header_bg_color,
                        foreground=self.text_color,
                        relief="flat",
                        font=('Calibri', 10, 'bold'))

        style.map("Treeview.Heading",
                  relief=[('active', 'flat'), ('pressed', 'flat')],
                  background=[('active', self.header_bg_color),
                              ('pressed', self.header_bg_color)])


        if hasattr(self, 'threat_table') and self.threat_table:
            self.threat_table.tag_configure('blocked',
                                            foreground='gray50' if self.current_theme_mode == "Light" else "gray30",
                                            font=('Calibri', 9, 'overstrike'))

    def load_history_for_date(self):
        date = self.history_date_entry_var.get()
        try:
            datetime.datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            self._log_message_app_event("ERROR: Неправильний формат дати."); return
        self.clear_current_table_view_and_data(is_loading_history=True)
        alerts, details, _, logs = data_handlers.load_history_log_for_date_str(date)
        for m in logs: self._log_message_app_event(m)
        self.all_threat_data_history = alerts;
        self.threat_details_json.update(details)
        self.populate_table_with_history()
        if self.all_threat_data_history:
            hist_iids_in_table = [item_id for item_id in self.threat_table.get_children('') if
                                  item_id.startswith("hist_")]
            if hist_iids_in_table:
                first_hist_id = hist_iids_in_table[0]
                if self.threat_table.exists(first_hist_id):
                    self.threat_table.see(first_hist_id);
                    self.threat_table.selection_set(first_hist_id)
                    self.on_threat_select(None)
        self.apply_filter()

    def clear_current_table_view_and_data(self, is_loading_history=False):
        if hasattr(self, 'threat_table'):
            for i in self.threat_table.get_children(): self.threat_table.delete(i)
        if hasattr(self, 'packet_details_text'): self.packet_details_text.delete("1.0", TK_END)
        if hasattr(self, 'ai_analysis_text'): self.ai_analysis_text.delete("1.0", TK_END)
        if not is_loading_history:
            self.aggregated_event_id_counter = 0;
            self.live_aggregated_threats.clear()
            self.all_threat_data_history.clear();
            self.threat_details_json.clear()
            self._log_message_app_event("INFO: Таблиця та всі дані очищені.")
        else:
            self.all_threat_data_history.clear()
            self.threat_details_json = {k: v for k, v in self.threat_details_json.items() if not k.startswith("hist_")}

    def apply_filter(self, *args):
        if not hasattr(self, 'threat_table'): return
        term = self.filter_entry_var.get().lower()
        sel = self.threat_table.selection()[0] if self.threat_table.selection() else None
        if term or self.threat_table.get_children():
            for i in self.threat_table.get_children(): self.threat_table.delete(i)
        new_sel, first_match = None, None;
        key, val = None, None
        if ":" in term: p = term.split(":", 1); key = p[0] if p[0] in config.THREAT_TABLE_COLS_INTERNAL else None; val = \
        p[1] if key else None
        datasets = []
        for data in self.live_aggregated_threats.values(): datasets.append(
            (data['table_iid'], data['data_for_display']))
        for iid_hist, d_tuple_hist, _ in self.all_threat_data_history:
            adapted_hist = d_tuple_hist
            if len(d_tuple_hist) != len(config.THREAT_TABLE_COLS_INTERNAL):
                if len(d_tuple_hist) == len(config.THREAT_TABLE_COLS_INTERNAL) - 1:
                    adapted_hist = (d_tuple_hist[0], 1) + d_tuple_hist[1:]
                else:
                    continue
            datasets.append((iid_hist, adapted_hist))
        for iid, data_tuple in datasets:
            match = False;
            if not term:
                match = True
            elif key and val is not None:
                try:
                    match = val in str(data_tuple[config.THREAT_TABLE_COLS_INTERNAL.index(key)]).lower()
                except:
                    match = any(term in str(v).lower() for v in data_tuple)
            else:
                match = any(term in str(v).lower() for v in data_tuple)
            if match:
                if not self.threat_table.exists(iid): self.threat_table.insert("", "end", iid=iid, values=data_tuple)
                if not first_match: first_match = iid
                if iid == sel: new_sel = iid
        final_sel = new_sel if new_sel and self.threat_table.exists(new_sel) else (
            first_match if first_match and self.threat_table.exists(first_match) else None)
        if final_sel: self.threat_table.selection_set(final_sel); self.threat_table.focus(
            final_sel); self.threat_table.see(final_sel)
        if self.threat_table.selection():
            self.on_threat_select(None)
        else:
            if hasattr(self, 'packet_details_text'): self.packet_details_text.delete("1.0", TK_END)
            if hasattr(self, 'ai_analysis_text'): self.ai_analysis_text.delete("1.0", TK_END)

    def clear_filter(self):
        self.filter_entry_var.set("");
        if hasattr(self, 'packet_details_text') and not (
                hasattr(self, 'threat_table') and self.threat_table.get_children()):
            self.packet_details_text.delete("1.0", TK_END)
            if hasattr(self, 'ai_analysis_text'): self.ai_analysis_text.delete("1.0", TK_END)

    def _sniffer_thread_target(self):
        if not self.selected_interface_name: print("CRITICAL: Interface not set in sniffer thread."); self.after(0,
                                                                                                                 self._handle_sniffer_thread_failure); return
        try:
            app_ref = self
            sniff(iface=self.selected_interface_name, prn=lambda p: app_ref.process_packet_wrapper(p),
                  stop_filter=lambda p: app_ref.stop_sniffing_event.is_set(), store=0)
        except Exception as e:
            print(f"SNIFFER CRASH: {type(e).__name__} - {e}"); self.after(0, lambda: self._log_message_app_event(
                f"SNIFF_ERR:{e}")); self.after(0, self._handle_sniffer_thread_failure)

    def _handle_sniffer_thread_failure(self):
        self._log_message_app_event("ERROR: Sniffer thread ended. Monitoring stopped.")
        if hasattr(self, 'start_button'): self.start_button.configure(
            state="normal" if self.interface_names else "disabled")
        if hasattr(self, 'stop_button'): self.stop_button.configure(state="disabled")
        if hasattr(self, 'interface_menu') and self.interface_names: self.interface_menu.configure(state="normal")
        if hasattr(self, 'update_feeds_button'): self.update_feeds_button.configure(state="normal")

    def process_packet_wrapper(self, packet):
        if not hasattr(self, 'alert_threat'): print(f"FATAL in wrapper: no alert_threat on {id(self)}"); return
        if self.stop_sniffing_event.is_set(): return
        alerts = sniffer_logic.process_packet_for_threats(packet, self.bad_ips_info, self.bad_domains_info)
        for data in alerts: self.alert_threat(data["packet_info"], data["indicator_type"], data["indicator_value"],
                                              data["alert_metadata"], data["packet_summary_str"])

    def _log_message_app_event(self, message):
        def update_gui():
            if hasattr(self, 'log_text') and self.log_text.winfo_exists():
                self.log_text.configure(state="normal");
                time_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3];
                lvl, msg_text = "", message
                if isinstance(message, str) and ":" in message: p = message.split(":", 1); l_test = p[
                    0].strip().upper();
                if l_test in ["INFO", "WARNING", "ERROR", "CRITICAL"]: lvl, msg_text = f"[{l_test}] ", p[1].strip()
                self.log_text.insert(TK_END, f"{time_str}: {lvl}{msg_text}\n");
                self.log_text.see(TK_END);
                self.log_text.configure(state="disabled")

        if hasattr(self, 'after'):
            self.after(0, update_gui)
        else:
            print(f"LOG (No GUI): {message}")

    def start_sniffing(self):
        iface = self.interface_var.get()
        if not iface or iface == "Немає інтерфейсів": self._log_message_app_event("WARN: Select interface."); return
        self._log_message_app_event("INFO: Clearing previous live aggregated alerts...")
        for iid in [d['table_iid'] for d in self.live_aggregated_threats.values()]:
            if hasattr(self, 'threat_table') and self.threat_table.exists(iid): self.threat_table.delete(iid)
        self.live_aggregated_threats.clear();
        self.aggregated_event_id_counter = 0
        self.threat_details_json = {k: v for k, v in self.threat_details_json.items() if not k.startswith("live_agg_")}
        self.selected_interface_name = iface;
        self._log_message_app_event(f"INFO: Starting monitoring on: {iface}");
        self.stop_sniffing_event.clear()
        try:
            self.sniffing_thread = threading.Thread(target=self._sniffer_thread_target, daemon=True);
            self.sniffing_thread.start()
            self.start_button.configure(state="disabled");
            self.stop_button.configure(state="normal")
            self.interface_menu.configure(state="disabled");
            if hasattr(self, 'update_feeds_button'): self.update_feeds_button.configure(state="disabled")
        except Exception as e:
            self._log_message_app_event(f"ERROR: Start sniffer thread: {e}"); self._handle_sniffer_thread_failure()

    def stop_sniffing(self):
        if self.sniffing_thread and self.sniffing_thread.is_alive(): self.stop_sniffing_event.set(); self._log_message_app_event(
            "INFO: Monitoring stopped.")
        if hasattr(self, 'start_button'): self.start_button.configure(
            state="normal" if self.interface_names else "disabled")
        if hasattr(self, 'stop_button'): self.stop_button.configure(state="disabled")
        if hasattr(self, 'interface_menu') and self.interface_names: self.interface_menu.configure(state="normal")
        if hasattr(self, 'update_feeds_button'): self.update_feeds_button.configure(state="normal")

    def trigger_feed_update(self):
        self._log_message_app_event("INFO: Updating feeds...")
        if hasattr(self, 'update_feeds_button'): self.update_feeds_button.configure(state="disabled",
                                                                                    text="Updating...")
        if hasattr(self, 'start_button'): self.start_button.configure(state="disabled")

        def task():
            logs_u = data_handlers.update_local_feed_files();
            [self._log_message_app_event(m) for m in logs_u]
            self.bad_ips_info, self.bad_domains_info, load_logs = data_handlers.load_all_feeds_data();
            [self._log_message_app_event(m) for m in load_logs]
            if hasattr(self, 'after'): self.after(0, self.reenable_feed_update_button); self.after(0, self.apply_filter)
            self._log_message_app_event("INFO: Feeds updated.")

        threading.Thread(target=task, daemon=True).start()

    def reenable_feed_update_button(self):
        if hasattr(self, 'update_feeds_button'): self.update_feeds_button.configure(state="normal", text="Оновити Фіди")
        if hasattr(self, 'start_button'): self.start_button.configure(
            state="normal" if self.interface_names else "disabled")

    def on_closing(self):
        self.stop_sniffing(); self._save_session_state_on_exit(); self.destroy()

    def _save_session_state_on_exit(self):
        """Збирає дані для сесії та викликає data_handlers для збереження."""
        session_data_to_save = {
            "all_threat_data": self.all_threat_data_history,
            "threat_details_json": self.threat_details_json,

        }
        log_msg = data_handlers.save_session_state_to_file(session_data_to_save)
        print(f"SESSION_SAVE_LOG: {log_msg}")

    def on_closing(self):
        self._log_message_app_event("INFO: Застосунок закривається...")
        print("INFO: Application is closing, attempting to stop sniffing and save session...")
        self.stop_sniffing()
        self._save_session_state_on_exit()
        self.destroy()
    def trigger_openai_analysis(self):
        if not (hasattr(self, 'packet_details_text') and hasattr(self, 'ai_analysis_text') and hasattr(self,
                                                                                                       'analyze_ai_button')):
            self._log_message_app_event("ERROR: Віджети для OpenAI аналізу не повністю ініціалізовані.")
            return

        current_json_log = self.packet_details_text.get("1.0", "end-1c").strip()
        if not current_json_log or current_json_log.startswith('{"error":'):
            self._log_message_app_event("INFO: Немає валідних деталей загрози для аналізу OpenAI.")
            messagebox.showinfo("Аналіз OpenAI", "Будь ласка, оберіть валідний алерт з деталями для аналізу.")
            return

        self._log_message_app_event("INFO: Відправка логу на аналіз до OpenAI...")
        self.ai_analysis_text.delete("1.0", TK_END)
        self.ai_analysis_text.insert("1.0", "Аналіз OpenAI триває, зачекайте...")
        self.analyze_ai_button.configure(state="disabled", text="Аналіз...")

        def ai_task():
            analysis_result, error_message = ai_analyzer.analyze_log_with_openai(current_json_log)

            def update_ui_with_ai_result():
                self.ai_analysis_text.delete("1.0", TK_END)
                if error_message:
                    self._log_message_app_event(f"ERROR (OpenAI): {error_message}")
                    self.ai_analysis_text.insert("1.0", f"Помилка аналізу OpenAI: {error_message}")
                elif analysis_result:
                    self._log_message_app_event("INFO: Аналіз від OpenAI отримано.")
                    self.ai_analysis_text.insert("1.0", analysis_result)
                else:
                    self._log_message_app_event("WARNING (OpenAI): Відповідь від OpenAI порожня.")
                    self.ai_analysis_text.insert("1.0", "Не вдалося отримати аналіз від OpenAI.")

                if hasattr(self, 'analyze_ai_button'):
                    self.analyze_ai_button.configure(state="normal", text="Аналізувати з OpenAI")

            if hasattr(self, 'after'): self.after(0, update_ui_with_ai_result)

        threading.Thread(target=ai_task, daemon=True).start()


if __name__ == "__main__":
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    is_admin = False
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        if platform.system() == "Windows":
            import ctypes

            try:
                is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
            except Exception as e_admin:
                print(f"[ADMIN CHECK ERR] {e_admin}")
    if not is_admin and platform.system() == "Windows":
        print("!!! УВАГА: Для блокування IP потрібні права адміністратора. !!!")


    app = SimpleIDS_IPS_App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
