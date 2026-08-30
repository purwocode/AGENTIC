"""Tests for the agents module."""
import unittest

from attack_surface.agents import (
    AgentTurn, ZeroDayAgent, build_agents, build_council_agents
)
from attack_surface.models import ModelAdapter


class MockModelAdapter:
    """Mock model adapter for testing."""
    
    def __init__(self, name: str, response: str = "Test response"):
        self.name = name
        self._response = response
    
    def complete(self, prompt: str) -> str:
        return f"{self._response}: {prompt[:50]}..."


class AgentTurnTests(unittest.TestCase):
    """Test AgentTurn dataclass."""
    
    def test_creates_agent_turn(self) -> None:
        """Should create an agent turn with required fields."""
        turn = AgentTurn(
            agent="TestAgent",
            model="test-model",
            response="Test response"
        )
        
        self.assertEqual(turn.agent, "TestAgent")
        self.assertEqual(turn.model, "test-model")
        self.assertEqual(turn.response, "Test response")
        self.assertEqual(turn.round_number, 1)
    
    def test_agent_turn_is_frozen(self) -> None:
        """AgentTurn should be immutable."""
        turn = AgentTurn("Agent", "model", "response")
        
        with self.assertRaises(Exception):
            turn.agent = "NewAgent"


class ZeroDayAgentTests(unittest.TestCase):
    """Test ZeroDayAgent class."""
    
    def test_creates_agent(self) -> None:
        """Should create an agent with name, instruction, and model."""
        model = MockModelAdapter("test-model")
        agent = ZeroDayAgent(
            name="TestAgent",
            instruction="Test instruction",
            model=model
        )
        
        self.assertEqual(agent.name, "TestAgent")
        self.assertEqual(agent.instruction, "Test instruction")
        self.assertEqual(agent.model.name, "test-model")
    
    def test_respond_returns_agent_turn(self) -> None:
        """Should return AgentTurn when responding."""
        model = MockModelAdapter("test-model", "Analysis complete")
        agent = ZeroDayAgent(
            name="VulnHunter",
            instruction="Find vulnerabilities",
            model=model
        )
        
        turn = agent.respond(
            user_request="Find SQL injection",
            context=[],
            target_info="https://example.com",
            attack_phase="reconnaissance",
            round_number=1
        )
        
        self.assertIsInstance(turn, AgentTurn)
        self.assertEqual(turn.agent, "VulnHunter")
        self.assertEqual(turn.model, "test-model")
        self.assertIn("Analysis complete", turn.response)
    
    def test_respond_includes_context(self) -> None:
        """Should include previous context in prompt."""
        model = MockModelAdapter("test-model")
        agent = ZeroDayAgent("TestAgent", "instruction", model)
        
        context = [
            AgentTurn("PrevAgent1", "model1", "Found endpoint /api/login"),
            AgentTurn("PrevAgent2", "model2", "Detected SQL injection")
        ]
        
        turn = agent.respond(
            "Continue analysis",
            context,
            "https://target.com",
            "exploitation",
            2
        )
        
        self.assertEqual(turn.round_number, 2)
    
    def test_agent_is_frozen(self) -> None:
        """Agent should be immutable."""
        model = MockModelAdapter("test-model")
        agent = ZeroDayAgent("TestAgent", "instruction", model)
        
        with self.assertRaises(Exception):
            agent.name = "NewName"


class BuildAgentsTests(unittest.TestCase):
    """Test build_agents function."""
    
    def test_requires_minimum_five_models(self) -> None:
        """Should require at least 5 models."""
        models = [MockModelAdapter(f"model-{i}") for i in range(4)]
        
        with self.assertRaises(ValueError):
            build_agents(models)
    
    def test_creates_five_specialized_agents(self) -> None:
        """Should create 5 specialized agents."""
        models = [MockModelAdapter(f"model-{i}") for i in range(5)]
        agents = build_agents(models)
        
        self.assertEqual(len(agents), 5)
        
        agent_names = {a.name for a in agents}
        expected_names = {
            "ReconAgent",
            "VulnHunterAgent",
            "ExploitDevAgent",
            "PoCValidatorAgent",
            "EvidenceCollectorAgent"
        }
        self.assertEqual(agent_names, expected_names)
    
    def test_agents_have_correct_models(self) -> None:
        """Each agent should have its assigned model."""
        models = [MockModelAdapter(f"model-{i}") for i in range(5)]
        agents = build_agents(models)
        
        # Recon agent should have first model
        recon = next(a for a in agents if a.name == "ReconAgent")
        self.assertEqual(recon.model.name, "model-0")
        
        # Evidence agent should have last model
        evidence = next(a for a in agents if a.name == "EvidenceCollectorAgent")
        self.assertEqual(evidence.model.name, "model-4")
    
    def test_agents_have_specialized_instructions(self) -> None:
        """Each agent should have role-specific instructions."""
        models = [MockModelAdapter(f"model-{i}") for i in range(5)]
        agents = build_agents(models)
        
        recon = next(a for a in agents if a.name == "ReconAgent")
        self.assertIn("reconnaissance", recon.instruction.lower())
        
        exploit = next(a for a in agents if a.name == "ExploitDevAgent")
        self.assertIn("exploit", exploit.instruction.lower())
    
    def test_build_council_agents_is_alias(self) -> None:
        """build_council_agents should be alias for build_agents."""
        models = [MockModelAdapter(f"model-{i}") for i in range(5)]
        
        agents1 = build_agents(models)
        agents2 = build_council_agents(models)
        
        self.assertEqual(len(agents1), len(agents2))
        for a1, a2 in zip(agents1, agents2):
            self.assertEqual(a1.name, a2.name)


if __name__ == "__main__":
    unittest.main()
