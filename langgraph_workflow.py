# langgraph_workflow.py - LangGraph Vulnerability Detection Workflow
from typing import TypedDict, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END, START
from langgraph.prebuilt import ToolNode
import os
import logging
from datetime import datetime
import json
import asyncio
from vulnerability_agents import (
    SastAgent,
    DependencyAgent,
    CveAgent,
    LlmAnalysisAgent,
    MitigationAgent,
    ReportAgent
)

logger = logging.getLogger(__name__)

class VulnerabilityState(TypedDict):
    """State schema for the vulnerability detection workflow"""
    scan_id: str
    config: Dict[str, Any]
    files: List[Dict[str, Any]]
    scan_options: Dict[str, bool]
    results: Dict[str, Any]
    progress: int
    current_step: str
    errors: List[str]
    step_results: Dict[str, Any]

class VulnerabilityDetectionWorkflow:
    """LangGraph workflow for comprehensive vulnerability detection"""
    
    def __init__(self):
        self.progress_callback = None
        self.initialize_agents()
        self.build_workflow()
    
    def initialize_agents(self):
        """Initialize all specialized agents"""
        try:
            self.sast_agent = SastAgent()
            self.dependency_agent = DependencyAgent()
            self.cve_agent = CveAgent()
            self.llm_agent = LlmAnalysisAgent()
            self.mitigation_agent = MitigationAgent()
            self.report_agent = ReportAgent()
            
            logger.info("All vulnerability detection agents initialized successfully")
        
        except Exception as e:
            logger.error(f"Error initializing agents: {str(e)}")
            raise
    
    def build_workflow(self):
        """Build the LangGraph workflow"""
        # Create the state graph
        workflow = StateGraph(VulnerabilityState)
        
        # Add nodes for each detection phase
        workflow.add_node("initialize", self.initialize_scan)
        workflow.add_node("static_analysis", self.run_static_analysis)
        workflow.add_node("dependency_analysis", self.analyze_dependencies)
        workflow.add_node("cve_analysis", self.analyze_cves)
        workflow.add_node("llm_analysis", self.run_llm_analysis)
        workflow.add_node("generate_mitigations", self.generate_mitigations)
        workflow.add_node("compile_report", self.compile_final_report)
        
        # Define the workflow edges
        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "static_analysis")
        workflow.add_conditional_edges(
            "static_analysis",
            self.should_analyze_dependencies,
            {
                "analyze_deps": "dependency_analysis",
                "skip_deps": "cve_analysis"
            }
        )
        workflow.add_edge("dependency_analysis", "cve_analysis")
        workflow.add_conditional_edges(
            "cve_analysis",
            self.should_run_llm_analysis,
            {
                "run_llm": "llm_analysis",
                "skip_llm": "generate_mitigations"
            }
        )
        workflow.add_edge("llm_analysis", "generate_mitigations")
        workflow.add_edge("generate_mitigations", "compile_report")
        workflow.add_edge("compile_report", END)
        
        # Compile the workflow
        self.graph = workflow.compile()
        logger.info("LangGraph workflow compiled successfully")
    
    def run(self, initial_state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
        """Run the complete vulnerability detection workflow"""
        self.progress_callback = progress_callback
        
        try:
            # Convert to proper state format
            state = VulnerabilityState(
                scan_id=initial_state["scan_id"],
                config=initial_state["config"],
                files=initial_state["files"],
                scan_options=initial_state["scan_options"],
                results=initial_state["results"],
                progress=initial_state["progress"],
                current_step="initializing",
                errors=[],
                step_results={}
            )
            
            # Execute the workflow
            final_state = self.graph.invoke(state)
            
            return final_state
        
        except Exception as e:
            logger.error(f"Workflow execution failed: {str(e)}")
            raise
    
    def update_progress(self, state: VulnerabilityState, progress: int, message: str):
        """Update progress and emit to callback"""
        state["progress"] = progress
        if self.progress_callback:
            self.progress_callback(progress, message)
        logger.info(f"Progress: {progress}% - {message}")
    
    def initialize_scan(self, state: VulnerabilityState) -> VulnerabilityState:
        """Initialize the vulnerability scan"""
        try:
            self.update_progress(state, 10, "Initializing vulnerability scan...")
            
            state["current_step"] = "initialization"
            state["step_results"]["initialization"] = {
                "files_count": len(state["files"]),
                "scan_options": state["scan_options"],
                "start_time": datetime.utcnow().isoformat()
            }
            
            # Validate files and configuration
            valid_files = []
            for file_info in state["files"]:
                if self.is_scannable_file(file_info):
                    valid_files.append(file_info)
            
            state["files"] = valid_files
            state["step_results"]["initialization"]["valid_files_count"] = len(valid_files)
            
            self.update_progress(state, 15, f"Initialized scan for {len(valid_files)} files")
            
            return state
        
        except Exception as e:
            logger.error(f"Initialization failed: {str(e)}")
            state["errors"].append(f"Initialization error: {str(e)}")
            return state
    
    def run_static_analysis(self, state: VulnerabilityState) -> VulnerabilityState:
        """Run static analysis security testing (SAST)"""
        try:
            if not state["scan_options"].get("sast_enabled", True):
                self.update_progress(state, 30, "Skipping static analysis (disabled)")
                return state
            
            self.update_progress(state, 20, "Running static code analysis...")
            state["current_step"] = "static_analysis"
            
            # Run SAST analysis
            sast_results = self.sast_agent.analyze_files(state["files"])
            
            state["step_results"]["static_analysis"] = sast_results
            state["results"]["vulnerabilities"].extend(sast_results.get("vulnerabilities", []))
            
            vuln_count = len(sast_results.get("vulnerabilities", []))
            self.update_progress(state, 30, f"Static analysis complete. Found {vuln_count} potential vulnerabilities")
            
            return state
        
        except Exception as e:
            logger.error(f"Static analysis failed: {str(e)}")
            state["errors"].append(f"Static analysis error: {str(e)}")
            return state
    
    def analyze_dependencies(self, state: VulnerabilityState) -> VulnerabilityState:
        """Analyze project dependencies for vulnerabilities"""
        try:
            self.update_progress(state, 40, "Analyzing project dependencies...")
            state["current_step"] = "dependency_analysis"
            
            # Run dependency analysis
            dep_results = self.dependency_agent.analyze_dependencies(state["files"])
            
            state["step_results"]["dependency_analysis"] = dep_results
            state["results"]["dependencies"].extend(dep_results.get("dependencies", []))
            state["results"]["vulnerabilities"].extend(dep_results.get("vulnerable_dependencies", []))
            
            dep_count = len(dep_results.get("dependencies", []))
            vuln_deps = len(dep_results.get("vulnerable_dependencies", []))
            
            self.update_progress(state, 50, f"Dependency analysis complete. {dep_count} dependencies, {vuln_deps} vulnerable")
            
            return state
        
        except Exception as e:
            logger.error(f"Dependency analysis failed: {str(e)}")
            state["errors"].append(f"Dependency analysis error: {str(e)}")
            return state
    
    def analyze_cves(self, state: VulnerabilityState) -> VulnerabilityState:
        """Analyze and enrich vulnerabilities with CVE/CWE data"""
        try:
            if not state["scan_options"].get("cve_lookup", True):
                self.update_progress(state, 70, "Skipping CVE/CWE lookup (disabled)")
                return state
            
            self.update_progress(state, 60, "Looking up CVE/CWE information...")
            state["current_step"] = "cve_analysis"
            
            # Get existing vulnerabilities
            vulnerabilities = state["results"]["vulnerabilities"]
            
            # Enrich with CVE/CWE data
            cve_results = self.cve_agent.enrich_vulnerabilities(vulnerabilities)
            
            state["step_results"]["cve_analysis"] = cve_results
            state["results"]["cves"].extend(cve_results.get("cves", []))
            state["results"]["cwes"].extend(cve_results.get("cwes", []))
            
            # Update vulnerabilities with CVE/CWE info
            state["results"]["vulnerabilities"] = cve_results.get("enriched_vulnerabilities", vulnerabilities)
            
            cve_count = len(cve_results.get("cves", []))
            cwe_count = len(cve_results.get("cwes", []))
            
            self.update_progress(state, 70, f"CVE/CWE analysis complete. {cve_count} CVEs, {cwe_count} CWEs identified")
            
            return state
        
        except Exception as e:
            logger.error(f"CVE analysis failed: {str(e)}")
            state["errors"].append(f"CVE analysis error: {str(e)}")
            return state
    
    def run_llm_analysis(self, state: VulnerabilityState) -> VulnerabilityState:
        """Run deep LLM-based code analysis using Gemini"""
        try:
            if not state["scan_options"].get("llm_analysis", True):
                self.update_progress(state, 85, "Skipping LLM analysis (disabled)")
                return state
            
            self.update_progress(state, 75, "Running AI-powered deep code analysis...")
            state["current_step"] = "llm_analysis"
            
            # Run LLM analysis with Gemini
            llm_results = self.llm_agent.analyze_code(
                state["files"],
                existing_vulnerabilities=state["results"]["vulnerabilities"],
                deep_analysis=state["scan_options"].get("deep_analysis", False)
            )
            
            state["step_results"]["llm_analysis"] = llm_results
            
            # Merge LLM findings with existing results
            state["results"]["vulnerabilities"].extend(llm_results.get("new_vulnerabilities", []))
            state["results"]["recommendations"].extend(llm_results.get("recommendations", []))
            
            new_vulns = len(llm_results.get("new_vulnerabilities", []))
            recommendations = len(llm_results.get("recommendations", []))
            
            self.update_progress(state, 85, f"AI analysis complete. {new_vulns} additional vulnerabilities, {recommendations} recommendations")
            
            return state
        
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            state["errors"].append(f"LLM analysis error: {str(e)}")
            return state
    
    def generate_mitigations(self, state: VulnerabilityState) -> VulnerabilityState:
        """Generate mitigation strategies for identified vulnerabilities"""
        try:
            self.update_progress(state, 90, "Generating mitigation strategies...")
            state["current_step"] = "mitigation_generation"
            
            # Generate mitigations for all vulnerabilities
            mitigation_results = self.mitigation_agent.generate_mitigations(
                state["results"]["vulnerabilities"]
            )
            
            state["step_results"]["mitigation_generation"] = mitigation_results
            
            # Update vulnerabilities with mitigation info
            state["results"]["vulnerabilities"] = mitigation_results.get("vulnerabilities_with_mitigations", [])
            state["results"]["recommendations"].extend(mitigation_results.get("general_recommendations", []))
            
            mitigations_count = len([v for v in state["results"]["vulnerabilities"] if v.get("mitigation")])
            
            self.update_progress(state, 95, f"Generated {mitigations_count} mitigation strategies")
            
            return state
        
        except Exception as e:
            logger.error(f"Mitigation generation failed: {str(e)}")
            state["errors"].append(f"Mitigation generation error: {str(e)}")
            return state
    
    def compile_final_report(self, state: VulnerabilityState) -> VulnerabilityState:
        """Compile the final vulnerability report"""
        try:
            self.update_progress(state, 98, "Compiling final report...")
            state["current_step"] = "report_compilation"
            
            # Generate comprehensive report
            report_results = self.report_agent.compile_report(
                vulnerabilities=state["results"]["vulnerabilities"],
                dependencies=state["results"]["dependencies"],
                cves=state["results"]["cves"],
                cwes=state["results"]["cwes"],
                recommendations=state["results"]["recommendations"],
                scan_metadata={
                    "scan_id": state["scan_id"],
                    "files_scanned": len(state["files"]),
                    "scan_options": state["scan_options"],
                    "errors": state["errors"],
                    "step_results": state["step_results"]
                }
            )
            
            state["step_results"]["report_compilation"] = report_results
            state["results"]["summary"] = report_results.get("summary", {})
            state["results"]["metadata"] = report_results.get("metadata", {})
            
            # Final progress update
            total_vulns = len(state["results"]["vulnerabilities"])
            self.update_progress(state, 100, f"Scan complete! Found {total_vulns} total security issues")
            
            return state
        
        except Exception as e:
            logger.error(f"Report compilation failed: {str(e)}")
            state["errors"].append(f"Report compilation error: {str(e)}")
            return state
    
    # Conditional edge functions
    def should_analyze_dependencies(self, state: VulnerabilityState) -> str:
        """Determine if dependency analysis should be run"""
        return "analyze_deps" if state["scan_options"].get("dependency_scan", True) else "skip_deps"
    
    def should_run_llm_analysis(self, state: VulnerabilityState) -> str:
        """Determine if LLM analysis should be run"""
        return "run_llm" if state["scan_options"].get("llm_analysis", True) else "skip_llm"
    
    def is_scannable_file(self, file_info: Dict[str, Any]) -> bool:
        """Check if a file can be scanned for vulnerabilities"""
        try:
            filename = file_info.get("name", "").lower()
            
            # Supported file extensions
            code_extensions = {
                '.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.php',
                '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.sh',
                '.html', '.jsx', '.tsx', '.vue', '.sql'
            }
            
            config_extensions = {
                '.json', '.yml', '.yaml', '.xml', '.ini', '.cfg', '.conf',
                '.toml', '.properties'
            }
            
            dependency_files = {
                'requirements.txt', 'package.json', 'composer.json', 'gemfile',
                'pom.xml', 'build.gradle', 'cargo.toml', 'go.mod', 'pipfile'
            }
            
            # Check if file is scannable
            file_ext = '.' + filename.split('.')[-1] if '.' in filename else ''
            base_name = filename.lower()
            
            return (
                file_ext in code_extensions or
                file_ext in config_extensions or
                base_name in dependency_files or
                filename.endswith('.lock')
            )
        
        except Exception as e:
            logger.error(f"Error checking file scannability: {str(e)}")
            return False