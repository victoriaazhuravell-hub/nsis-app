import streamlit as st
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import datetime
import time

class SecurityAuditTrail:
    def __init__(self):
        if 'audit_log' not in st.session_state:
            st.session_state.audit_log = []

    def add_entry(self, action, severity="INFO"):
        dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.audit_log.append({
            "Timestamp": dt,
            "Action": action,
            "Severity": severity,
            "User": "Zhuravel_V"
        })

class NetworkEngine:
    def __init__(self):
        self.graph = nx.Graph()
        self.build_infrastructure()

    def build_infrastructure(self):
        nodes_data = [
            ("Gateway_Alpha", "Core_Switch", 2),
            ("Core_Switch", "Server_Cluster", 5),
            ("Core_Switch", "User_Segment_A", 12),
            ("Core_Switch", "User_Segment_B", 15),
            ("Server_Cluster", "DB_Production", 3),
            ("Server_Cluster", "Backup_Node", 7),
            ("User_Segment_A", "Print_Server", 4),
            ("User_Segment_B", "Print_Server", 8),
            ("Gateway_Alpha", "Cloud_Edge", 35),
            ("Cloud_Edge", "External_SaaS", 90),
            ("DB_Production", "Backup_Node", 10)
        ]
        self.graph.add_weighted_edges_from(nodes_data)
        
        for node in self.graph.nodes():
            if "Server" in node or "DB" in node or "Core" in node:
                self.graph.nodes[node]['zone'] = "Restricted"
            else:
                self.graph.nodes[node]['zone'] = "General"

    def analyze_path(self, start, end):
        try:
            path = nx.dijkstra_path(self.graph, start, end, weight='weight')
            cost = nx.dijkstra_path_length(self.graph, start, end, weight='weight')
            zones = [self.graph.nodes[n]['zone'] for n in path]
            return {"path": path, "cost": cost, "zones": zones, "success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

def apply_custom_styles():
    st.markdown("""
        <style>
        .main { background-color: #f5f7f9; }
        .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #004a99; color: white; }
        .stMetric { background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .report-box { padding: 20px; border-left: 5px solid #004a99; background-color: #eef4ff; margin: 10px 0; }
        </style>
    """, unsafe_allow_html=True)

def main():
    apply_custom_styles()
    
    if 'net_engine' not in st.session_state:
        st.session_state.net_engine = NetworkEngine()
    if 'audit' not in st.session_state:
        st.session_state.audit = SecurityAuditTrail()
    
    engine = st.session_state.net_engine
    audit = st.session_state.audit

    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
        st.title("Admin Console")
        st.info("Operator: V. Zhuravel")
        st.divider()
        
        st.subheader("Control Panel")
        nodes = sorted(list(engine.graph.nodes()))
        src = st.selectbox("Source Node", nodes)
        dst = st.selectbox("Destination Node", nodes, index=1)
        
        st.divider()
        if st.button("RUN DIAGNOSTICS"):
            with st.spinner("Analyzing infrastructure..."):
                time.sleep(1)
                st.session_state.current_analysis = engine.analyze_path(src, dst)
                if st.session_state.current_analysis["success"]:
                    audit.add_entry(f"Path calculated: {src} to {dst}")
                else:
                    audit.add_entry(f"Failed analysis: {src} to {dst}", "CRITICAL")

    st.title("🌐 Network Security Intelligence System")
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Active Nodes", engine.graph.number_of_nodes())
    m2.metric("Connections", engine.graph.number_of_edges())
    m3.metric("System Status", "Operational", delta="Stable")
    m4.metric("Security Level", "L3 Tier")

    tab_vis, tab_data, tab_audit = st.tabs(["Topology Visualization", "Node Analytics", "Security Audit"])

    with tab_vis:
        col_graph, col_info = st.columns([2, 1])
        
        with col_graph:
            fig, ax = plt.subplots(figsize=(10, 7), facecolor='#f5f7f9')
            pos = nx.kamada_kawai_layout(engine.graph)
            
            nx.draw_networkx_edges(engine.graph, pos, alpha=0.2, edge_color="#2c3e50", ax=ax)
            
            node_colors = ['#e74c3c' if engine.graph.nodes[n]['zone'] == "Restricted" else '#3498db' for n in engine.graph.nodes()]
            nx.draw_networkx_nodes(engine.graph, pos, node_size=1200, node_color=node_colors, ax=ax)
            nx.draw_networkx_labels(engine.graph, pos, font_size=8, font_weight="bold", ax=ax)

            if 'current_analysis' in st.session_state:
                res = st.session_state.current_analysis
                if res["success"]:
                    p = res["path"]
                    edgelist = list(zip(p, p[1:]))
                    nx.draw_networkx_edges(engine.graph, pos, edgelist=edgelist, edge_color='#e67e22', width=3, ax=ax)
                    nx.draw_networkx_nodes(engine.graph, pos, nodelist=p, node_color='#f1c40f', node_size=1300, ax=ax)

            ax.set_axis_off()
            st.pyplot(fig)

        with col_info:
            st.subheader("Route Analysis")
            if 'current_analysis' in st.session_state:
                res = st.session_state.current_analysis
                if res["success"]:
                    st.markdown(f"""
                        <div class="report-box">
                            <b>Path:</b> {' → '.join(res['path'])}<br>
                            <b>Total Latency:</b> {res['cost']} ms<br>
                            <b>Hops:</b> {len(res['path'])-1}<br>
                            <b>Secure Zones:</b> {', '.join(set(res['zones']))}
                        </div>
                    """, unsafe_allow_html=True)
                    
                    csv = pd.DataFrame([res]).to_csv(index=False).encode('utf-8')
                    st.download_button("Export Results", csv, "analysis.csv", "text/csv")
                else:
                    st.error(res["error"])

    with tab_data:
        st.subheader("Infrastructure Inventory")
        df = pd.DataFrame([
            {"Node": n, "Zone": d['zone'], "Connections": len(list(engine.graph.neighbors(n)))}
            for n, d in engine.graph.nodes(data=True)
        ])
        st.dataframe(df, use_container_width=True)

    with tab_audit:
        st.subheader("System Access Log")
        log_df = pd.DataFrame(st.session_state.audit_log)
        if not log_df.empty:
            st.table(log_df.sort_index(ascending=False))
        
        if st.button("Clear Audit Trail"):
            st.session_state.audit_log = []
            st.rerun()

if __name__ == "__main__":
    main()