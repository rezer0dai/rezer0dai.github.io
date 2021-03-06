---
use_math: true
title: "Experimental techniques for Reinforcement Learning"
tags:
  - rewheeler
  - reinforcement learning
  - ai
  - research
  - her
---

{% include toc %}

# Project REWheeler

Reinforcement Learning project, which trying to address OpenAI Request for reseach for [HER](https://openai.com/blog/ingredients-for-robotics-research/) edition. And next iteration of original [Wheeler project](https://github.com/rezer0dai/wheeler).

I used [Reacher UnityML environment](https://github.com/Unity-Technologies/ml-agents/blob/master/docs/Learning-Environment-Examples.md) for testing rewheeler, where i did several [modifications](https://rezer0dai.github.io/rewheeler/#reacher-environment-unityml) to state representation, reward function, length of episode..

As a note project is heavily *Replay Buffer oriented*!

## HER : request for research
*Hindsight Experience Replay (**HER**)* : reinforcement learning algorithm that can learn from failure, and can learn successful policies on robotics problems from only sparse rewards.
<br/>In my words even if agent fails to achieve goal (goal-a), it achieves somethings. And that something (goal-b) will be not scattered, but will be evaluated with respect to policy and recorded state-action pairs we taken, but this time our objective will be not originally intended to reach goal-a but goal-b instead. This way we can introduce more closely related learning signal to goal based environment, while avoiding overcomplicated hand engineered reward functions (example 1/0 signal ~ goal was achieved or not).

However this technique has some potential limitations. For example we can not simply use n-step returns when it comes to [td-error](http://boris-belousov.net/2017/08/10/td-advantage-bellman/). This and some others improvements was highlighted at HER specific [OpenAI Rquest for research](https://openai.com/blog/ingredients-for-robotics-research/#requestsforresearchheredition) and i am trying to address some of those in this post and project itself.

**Why** is there problem with n-step while using HER ? Once we setup new goal and trying to calculate td-error it is OK for 1-step lookahead, as from both current state and following next state we ask current policy to get us new action taken with respect to new goal and comparing its outcomes. 
<br/>However if we try to do it with 2+ (n)state, then those states between current one and last n-state was taken with respect to different goals. It means n-state which was achieved via n-steps from current state is not usable for td-error under different goal, as current policy will unlikely choose same actions for given states but new goal, therefore our replay is useless for this purpose in this way.
<br/>But then, (how) can we introduce back n-state approximation ?
### Floating n-step
At first we can take a look how is TD error calculated :
```python
n_qa = self.ac_target(n_goals, n_states)
td_targets = n_rewards + n_discounts * n_qa
qa = self.ac_explorer(goals, states)
td_error = qa - td_targets
```
It is n-state td-error, but it caculates value for given state not n-step forward from it, utilizing it as n-state approximation is done via further discounting. Well, this may seems obvious, but from this point i did not had any objection to try Floating-N-Step approximation!

*In **floating n-step** every learning loop i select not 'fixed n for state', but k-step one where k is randomly selected from range <1,n>.*
On the other side disadvantage is that it takes more computation power as i need it to recalculate it every time as i want to re-randomize k for learning. However this approach theoretically should lead to better generalization and more efficient use of past experience, as we now are able to use n times more distinct td-errors to learn from one episode. [code](https://github.com/rezer0dai/rewheeler/blob/master/alchemy/agent.py) looks like :
```python
def _random_n_step(self, length):
    do_n_step = lambda n: self.n_step if not self.floating_step else random.randint(n, self.n_step)
    n_step = lambda i: do_n_step(1 if length-1>i+self.n_step else (length-i-1))
    return self._do_random_n_step(length, n_step)

def _do_random_n_step(self, length, n_step):
    n_steps = [ n_step(i) for i in range(length - self.n_step) ]
    indices = np.asarray(n_steps) + np.arange(len(n_steps))
    indices = np.hstack([indices, self.n_step*[-1]])
    return n_steps, indices
```
OK, but what it has in common with HER ? well, HER can be seen as natural floating n-step approximation extension.
As now in floating n step is natural to have k equal to 1 (with probability 1:n), which is exactly case of HER, and rest non 1 equal k steps transitions will be evaluated without HER(no goal replacement), while ratio (HER vs k-step) for td-error computation should be subject of hyperparameters tuning (**her_max_ratio**).
### N-step GAE
Another important part of reinforcement learning is credit assignment problem. Where there are multiple approaches to tackle it, namely [Rudder](https://arxiv.org/abs/1806.07857) which using LSTM and try to backtrack how to decompose reward based on contribution of particular action states transitions. Where other approach named [GAE using eligibility traces](https://arxiv.org/abs/1506.02438) looks at this problem from bit different different angle and using more straightforward approach (it is worth to check nice article explaining GAE and introducing [Online GAE](http://www.breloff.com/DeepRL-OnlineGAE/)) :

{:refdef: style="text-align: center;"}
![GAE](https://rezer0dai.github.io/assets/images/gae.png "http://www.breloff.com/DeepRL-OnlineGAE/")
{: refdef}

When i look from my perspective, neural net have lot of freedom to assign reward by themselves, as there is discounted subtraction of Value functions from different states, where neural net can 'tune' it by itself and figure out assignment of credit, while reward coming from environment can be understood just as signal not as an ultimate reward function which you need to handmade and your neural network should approximate. And by doing so it may be more natural to use sparse rewards, which will works really only like signal, instead.

This is how it looks at [code](https://github.com/higgsfield/RL-Adventure-2/blob/master/2.gae.ipynb) :
```python
def compute_gae(next_value, rewards, masks, values, gamma=0.99, tau=0.95):
    values = values + [next_value]
    gae = 0
    returns = []
    for step in reversed(range(len(rewards))):
        delta = rewards[step] + gamma * values[step + 1] * masks[step] - values[step]
        gae = delta + gamma * tau * masks[step] * gae
        returns.insert(0, gae + values[step])
    return returns
```
And once i look at it from more hacky standpoint, i never saw implementation for n-step gae, it always just recalc for whole episode and in td-error used for two following states (1-step lookahead). But there is little difference between classical n-step approach and gae in a way, that when we look how td-error is computed (see code snippet above) it is basically used for gradients ( in case of DDPG ) only first state and n-state! Rest is in n-step basically sum of discounted reward from state to n-state according to experience in environment, however what it should be for gae ?
{:refdef: style="text-align: center;"}
![Backward GAE](https://rezer0dai.github.io/assets/images/td_lambda_backward.jpg "R. S. Sutton and A. G. Barto: Reinforcement Learning: An Introduction")
{: refdef}
<br/>For GAE it is basically, as i look at it, credit assignment value, as from algorithm you can see only subtraction are active as basically every state between first and n-th one are canceling each other, and so only 'weighted' difference between state transitions are left - credit assigned, where reward from environment can really play only role of signal while Q-values between transitions are here the real deal!

### Conclusion
As a result you can use floating-n-step + HER + GAE in one shot, implementation is bit tricky on part with replay buffer, what to store, when and how to recalculate, but it appears to works good in my case. Also it is needed to be careful when you can use HER and when not, k-step and HER can not interleave each other in episode, same apply if we rerandomize for replay buffer floating n-step then HER can not be used. More quirks and tricks related you can find [here](https://github.com/rezer0dai/rewheeler/blob/master/alchemy/agent.py) and [here](https://github.com/rezer0dai/rewheeler/blob/master/utils/policy.py).

## Cross Algo Cooperation : PPO+DDPG
Reinforcement learning has several [algorithms](https://lilianweng.github.io/lil-log/2018/02/19/a-long-peek-into-reinforcement-learning.html) working over [policy gradients](https://lilianweng.github.io/lil-log/2018/04/08/policy-gradient-algorithms.html) methods (DDPG, PPO, TRPO, ACER, ..) or value functions (DQN). I prefer working with policy methods as it allows me to work on continuous action spaces more naturally, and i am especially inclined to DDPG due its nice workarounds with backpropagation of value function loss trough policy network and usage of replay buffer. However algorithm like PPO results in more smooth changes of policy per update and are on-policy driven. On the value functions front DQN algorithm achieved big success on variety of Atari games partially due to discrete action space and proved very efficient.

And there i was wondering if i can benefit from *different methods into single learning process*.
<br/>Lets at first see some learning stats on Reacher environment of DDPG and PPO respectivelly :

{:refdef: style="text-align: center;"}
![DDPG](https://rezer0dai.github.io/assets/images/ddpg.png "learning progress")
{: refdef}
.. as you can see DDPG is somehow fast to understand what it should do from start, i guess more informative gradient signal, but as learning progress it can stagnate on 'local minima' pretty long time (however that local minima could be because my substituted reward actually encourage different than default behaviour, as you can see from learning graph at notebook it actually keeps its cool and learn my reward function progresivelly all the time). You can check full training [here](https://rezer0dai.github.io/rewheeler/#jupyter-notebooks).

{:refdef: style="text-align: center;"}
![PPO](https://rezer0dai.github.io/assets/images/ppo.png "learning progress")
{: refdef}
.. on the otherside, you can see, that PPO is way too slow to catch up what todo at begining but do quite leaps once it figure it out, and can converge blazingly fast. You can check full training [here](https://rezer0dai.github.io/rewheeler/#jupyter-notebooks).
<br/>Actually this can be quite biased output on PPO vs Reacher, as i used bit [different PPO implementation](https://rezer0dai.github.io/rewheeler/#ppo), though in this case it actually helps to demonstrate potential of idea for cross cooperation.

So there i start thinking how to **combine** them to get benefits or both.
{:refdef: style="text-align: center;"}
![cross coop](https://rezer0dai.github.io/assets/images/coop_v2.png "cooperation schema")
{: refdef}
- **common replay buffer** :
  lets ppo take steps and ddpg replay from memory (other way around may do the job too, but you need to carefully recalculate probabilities of ppo making that action-state pairs if it comes from DDPG experience, while DDPG does not care about probabilities, so it is more natural fit)
- **synchronization** :
  With sharing experience only in direction ppo->ddpg is one sided cooperation, while it may work too, i would like to enforce more synchronization. So lets synchronize theirs Policy Neural Networks!
{:refdef: style="text-align: center;"}
![cross sync](https://rezer0dai.github.io/assets/images/sync.png "synchornization schema")
{: refdef}
  - every X-episodes synchronize ddpg explorer policy network from ppo as pattern, while ppo will get updated its explorer after every episode from ddpg for enhanced exploration ( as ddpg will update faster, but ppo updates are more stable )
  - i did several experiments and the one most (3+ times speedup for learning) payed of, when ddpg did learn only from experience of synced ppo algorithm, and ddpg itself was not actively used for interacting with environment while learning (actually it was used but only 1:10 due to simplicity of implementation), on the other side ppo explorer was synced every episode with ddpg one, and ddpg explorer was synced with ppo every second learning round of ppo
  - good results yields also when DDPG actively join exploration in environment, especially it manifest better learning from the beggining but worse at later stages ( inherited more of ddpg specifics in this environment ), but i changed there approach of synchronizing, every second PPO learning loop i exchanged full target+explorer networks ( full swap DDPG <-> PPO ), at [jupyter notebooks section](https://rezer0dai.github.io/rewheeler/#jupyter-notebooks) it is refered as coop_v2.

{:refdef: style="text-align: center;"}
![COOP_v1](https://rezer0dai.github.io/assets/images/coop_v1.png "coop_v1")
{: refdef}

### Conclusion
Test results of combining algorithms into one with cooperation seems promising, as we can see on this environment was achieved balance between pros and cons of both algorithms (slower learning at begining but still relatively fast, and good leaps towards mastering environment) and leads to successfully (and 3 times faster) solving environment (no divergence / oscilation, and both algorithms/agents learns how to approach environment even on its own ~ does not exhibit behaviour where one agent behave just randomly while the other making it up for it). I did not tried to combine Q-values with Policy Gradients but i think it is feasible, and can maybe brings some unexpected results, well TODO..

## MROCS : multiple rewards
One of the most tricky part of RL is engineering reward function which encourage behaviour which is nearly optimal for particular task. This is particulary tricky as the same reward function may encourage human to do task but not necessarily neural net with particular algorithm, and vice versa... Thats where emerged techniques like HER, which gives reward 0/1 based if goal was met or not. Or [novelity](https://arxiv.org/abs/1712.06560)/[curiosity](https://pathak22.github.io/noreward-rl/) driven, where reward is assigned based on how unexpected was state-action-nextstate transition.  On this front i was looking for balance complexity of reward engineering and simplicity of evaluation for neural net. 

When i was looking at navigation tasks it comes for me most natural way how to achieve it by **split** reward function, as an example instead of euclidian distance or punishing bad behaviour with big penalties, assign simple reward per dimension in HER style (1/0). 
{:refdef: style="text-align: center;"}
![MROCS](https://rezer0dai.github.io/assets/images/mrocs.png "MROCS schema")
{: refdef}
Here similarity between HER and MROCS is that it assign 1/0 rewards per **subtask** (dimension distance reached the goal or not, on X-Y-Z dimension in 3D) however it differs that trough loss function is pushed mean of all subtask rewards which make it non 1/0 signal anymore. At that end it may looks very similar to complex hand engineered reward functions, however engineering became far more easier, as only thing we need to hand made is to define goals / evaluation points, and rest is up to network and algorithm itself ~ how to maximize its mean in long run.

Whole mechanics behind that separation, is to use it on more complex task, but unfortunately i did not realized that test yet. As an example we can take tasks with fetching object and bringing it to destination. Here instead of only X-Y-Z rewards per dimension for location of arm, we can add also same for object, then another 1/0 reward if object is fetched, 1/0 rewards for reaching goal with fetched object per dimension.

### Multiple Agents
Actually my [original approach to separate subtask failed](https://rezer0dai.github.io/rewheeler/#critics-with-different-objective), and i come up with MROCS idea on different (multi agent) task after reading [MADDPG paper](https://arxiv.org/abs/1706.02275). MADDPG uses very nice trick, as critic is not used for testing in real environment but only during training time, therefore it may have access to more information during training than it have in testing (never used in testing to be precise, aka critic can learns whatever helps at training), while actor have access only to information he has access also in testing time. Therefore MADDPG critic access to both agents states, as multiagent environment, however in MROCS i forced critic to output also multiple rewards and maximize their mean as non-cooperation competitive game by single critic, alongside with some [other tricks](https://github.com/rezer0dai/MROCS/blob/master/brain.py) like bit different state-action pairs from replay buffer used for training. Which seems works [pretty well](https://github.com/rezer0dai/MROCS/blob/master/MROCS.ipynb) at least for Tenis UnityML environment.

From that point i moved to MROCS approach to output multiple values also for navigation, but this time, as described above, with more subtasks sparsely rewarded rather than complex single reward value per agent. And that i used for this [REWheeler project](https://github.com/rezer0dai/rewheeler) evaluated on [Reacher UnityML environment](https://github.com/Unity-Technologies/ml-agents/blob/master/docs/Learning-Environment-Examples.md).

### Conclusion
Separate task to several subtasks while using sparse rewards and let figure neural net to maximize total gain over episode, instead of hand engineer complex reward function, seems working well at least for HER approach, however i did not test it on more complex environments yet ( like fetch and reach, hand control, .. ).
<br/>Idea to critic having access during training to environment information what are not accessible during evaluation is quite elegant and have broader potential, however i did not experiment with it throughoutly yet.

## Noisy Network Head per Actor
Another interesting challenge in reinforcement learning to experiment with is exploration strategy. At first i used [OUNoise](https://en.wikipedia.org/wiki/Ornstein-Uhlenbeck_process) which is common choice and especially nice once you can run multiple environments at once using one actor but having OUNoise per environment emphatise more throughout exploration for single agent policy. On the other hand i abandon this approach as i realized that is not the method i want to use, at least not in general case. Why is that ?
<br/>Simple example is [MountainCar environment](https://medium.com/reinforcement-learning-w-policy-gradients/mountaincarcontinous-cheating-8446b09647ba), which is one of my favorite as it focus on problem where you need to do quite opposite actions for a moment to be able to achieve goal. And that is not so trivial to achieve, especially with random noise, as RL is bit tricky in a way you must experience good behaviour at least once to learn ~ well it depends on several aspects like how is reward function engineered, type of problem, algorithm used (HER, ..). 

Lets check [mountaincar reward function](https://github.com/openai/gym/blob/master/gym/envs/classic_control/continuous_mountain_car.py):
```python
def step(self, action):
  #...
  reward = 0
  if done:
    reward = 100.0
  reward-= math.pow(action[0],2)*0.1
  #...
```
we can see, that it encourages low power use, not anything to help agent to learn from experience, without achieved goal, how to reach goal. Therefore when you are unlucky you may never reach it, as critic can easily overfit to actor current behaviour and learns nothing useful at the end. 
However ... with OUNoise it wont happen, or at least very unlikely! To see why lets see how random noise will play in this environment alone, totaly random policy, vs OUNoise agent :
{% gist 10620e30f32c9d394f980851d8619132 %}
Random agent as expected get stuck 99% of times and nothing interesting going on, actually that one i would expect of random noise.But when we look at results from OUNoise agen, its totally different cup of tea, it is like expert behaviour, comparsion to random noise. And that said, our agent learns from solved trajectories and it learns only to optimize it trough given reward function, not actually figuring out how to get goal met in first place. 
Therefore, in my opinion, OUNoise can be very effective at some particular tasks but on the others it can bias exploration of agent which is core of learning.
Mostly for those reasons, but also for some others, i prefer [noisy networks](https://arxiv.org/abs/1706.10295), which adds Gaussian noise to parameters of network and not only to output itself. However i made few modifications to those. 
- Noisy Heads : OUNoise can be added per environment for single actor and so theoretically enforce better exploration, whereas with plain noisy networks you have one noise for one agent. For this purpose i allowed actor have multiple noise, sigma and noise, while sharing same network parameters for non-noisy deterministic part. This way i have multiple agents with same network but noise. Example implmenetation of forward push :
```python
def forward(self, data):
    for i, layer in enumerate(self.layers[:-1]):
        data = F.relu(layer(self.sigma[i], data))
    return self.layers[-1](self.sigma[-1], data)
```
- partial re-noise :
i re-noise only one noisy layer for noisy network rather than full noise randomization. No actual tests on this front, but sounds to me legit and more intuitive.

### Conclusion
For this project i prefer to use Noisy Networks, while i did some [modifications](https://github.com/rezer0dai/rewheeler/blob/master/utils/nes.py) which was not properly evaluated in general but as for this case, Reacher Environment, seems works and in future i plan to test those modification to Noisy Networks in better detail. 

On the bottom line, seems introducing many noisy heads does not help as much, contradictory it seems breaks training, though need better evaluation and code corrections (mainly at part of synchronizing target with multiple explorer heads).

## RNN with goal
As reinforcement learning tasks are sequence process by default, it sound for me more natural to encode state in form of hidden state of GRU rather than expect to be able to fit MDP to single state represenation by hand engineer or bunch of pixels. While RNN may be seen as natural fit for this, it becomes more tricky once you want to use approach like HER, as once you change goal your entire hidden state for given sequence of state-action pairs becomes invalid! But not necessary.. once you force RNN works only over state representation (pixels) and apply goal after RNN output, you can use RNN as intended. Though i see another problem with RNN, particulary usage of hidden state as state representation, where hidden state meaning/representation is changing with learning loops quite fast, so it need to be recalculated every so often which is performance overhead you need to deal with, likely pararelization is efficient choice as replay buffer can be utilized while learning.
### Conclusion
Again not properly tested, though i highlighted it in this section as it required quite [engineering efforts](https://github.com/rezer0dai/rewheeler/blob/master/utils/rnn.py), and i expect benefits out of it can manifest when used on raw input ( pixels -> pretrained CNN for features -> RNN -> goal -> action ).

## Implementation and Features
In this section i briefly introduce some features and will point readers to the source code.
### PPO
In this post i mentioned i am using PPO (alongside DDPG), though i mention several times replay buffer and soft actor critic in that context. Thats right, actually my implementation bit deviate from standard one exactly in those aspects. Main reason behind it was that i wanted in rewheeler use one or another algorithm (ppo/ddpg/dqn/..) interchangeable or in tandem (cooperatitive).
  - First for using it this way i needed to create *Policy Heads* for actor at top of its policy neural net architecture, which outputs distribution. For DDPG / DQN distribution outputs original predictions so its just dummy wrapper, while PPO / REINFORCE / TRPO outputs by nature distribution, then only one place which need to deal differently for dummy and normal distribution is when working with policy loss but this is easy to handle by checking active gradients.

```python
class DDPGDist():
    def __init__(self, actions):
        self.actions = actions
    def log_prob(self, actions):
        return torch.ones(actions.shape)
    def sample(self):
        return self.actions

class DDPG(nn.Module):
    def __init__(self):
        super().__init__()
    def forward(self, actions):
        dist = DDPGDist(actions)
        return dist

class PPO(nn.Module):
    def __init__(self, action_size):
        super().__init__()
        self.log_std = nn.Parameter(torch.zeros(1, action_size))
    def forward(self, mu):
        std = self.log_std.exp().expand_as(mu)
        dist = Normal(mu, std)
        return dist
```
  - second as DDPG using soft actor critic, implementation will be easier if PPO do the same. And it appears to work. But, it actually screams out to not to do it ([on vs off](https://leimao.github.io/blog/RL-On-Policy-VS-Off-Policy/), [ddpg maxQ](https://spinningup.openai.com/en/latest/algorithms/ddpg.html), [ppo explained](https://medium.com/@jonathan_hui/rl-proximal-policy-optimization-ppo-explained-77f014ec3f12) -> [ppo is on](https://spinningup.openai.com/en/latestnot to /algorithms/ppo.html)) as i make it more and more off-policy oriented. On the other side, this soft-actor-critic feature can be disabled, to original on-policy settings, pretty much easy with setting **tau_base=tau_final=1.** and synchronizing networks per update via **sync_delta=1**. I tested with tau=1e-3 and sync_delta=3 especially for purpose of cross-algorithm cooperation, for method where i want to sync only explorer networks and let target networks adapt via own learning, therefore running ppo also in this settings can better expose learning difference (no-cooperation vs cooperation). And also i guess, more tests on this front could be done (ideas : On vs Off policy PPO, how much off is too much, cooperation version of PPO, ..).
  - last issue was replay buffer, as on every implementation i saw does not use it directly, they just use buffer to keep memorized all experience from last learning loop to current one and then do random rollouts. But using replay buffer will easier my cross algo implementation. And in fact, when we look at common ppo rollout buffer approaches at implementation level it is the same as having replay buffer as small to cover exactly that amount of experience. Actually i doubled buffer size to contain experience time period from last two learning steps up to current one, and experimenting with td error prioritization as well.

### N-state
REWheeler framework allows you to stack 1..N states together, like multiple pixel screens across N-steps ( where N is chosen by configuration of [Bot](https://github.com/rezer0dai/rewheeler/blob/master/alchemy/bot.py) and [Encoder](https://github.com/rezer0dai/rewheeler/blob/master/utils/encoders.py) via **n_history** argument ). In addition this feature is built in [RNN](https://github.com/rezer0dai/rewheeler/blob/master/utils/rnn.py) as well - check forward + extract features methods. No need for environment itself to support it, framework can stack it for you.
### Encoders
Support of encoding state, from environment, trough different types of methods. Available to stack on top of each other. Example of encoders : RBF, Global normalization, Batch normalization, RNN. Implementation [here](https://github.com/rezer0dai/rewheeler/blob/master/utils/encoders.py).
### CrossBuffer
Replay Buffer capable of sharing experience for different algorithms, for now no prioritization for simplicity, thats future TODO. Implementation [here](https://github.com/rezer0dai/rewheeler/blob/master/utils/crossexp.py)
### Seed-ed episode re-run
If environment support running with seed, you can select how much times you want to run over same seed to gather more related sample trajectories for current policy, where noise will make difference between selection actions. Configure via **mcts_rounds** of [Env](https://github.com/rezer0dai/rewheeler/blob/master/alchemy/env.py). Another parameter **mcts_random_cap** is for making seed collisions as training progress, aka trying to start from same start state with same seed but later on with updated policy to confront out theoretical progress (learning from same state but from replay buffer vs real interaction), however in current approach it will lead more to overfiting to given seeds, i will update approach to reflect more true purpose without side effect of overfiting.
### Replay cleaning
As my adaptation of PPO algorithm works with replay buffer, i implemented testing feature, where you can deprioritize state-action transitions which are no more enough probable under PPO policy agent. Configurable trough **replay_cleaning** and **prob_treshold** of BrainDescription, for DDPG this configuration does not have effect.
### Online learning
In this framework i allow to learn from imidiate experience ( online ) for any type of algorithm, how much of imidiate experience to use you can configure via **fresh_frac** of BrainDescription.

### Actor-Critic design
  - Actor and Critic share Encoder layer
  - Encoder can be anything from RNN, RBF, normalizers, CNN, .. and any combination of those
  - DDPG / PPO and other algorithms for policy can be used interchangeably without modifying code, only need to engineer head for particular algorithm (to output/wrap actions to distribution)
  - Configurable how often to update target network, and how to clip gradients
  - possible to have multiple Critics per agent
  - possible to have multiple noise for agent, as well as have multiple agents
  - via multiple agents you can use framework on multiple agent competitive / cooperation task (using MADDPG idea via MROCS implementation)

### Task wrapper
All the magic of applying rewheeler framework to another task should happen in [task wrapper](https://github.com/rezer0dai/rewheeler/blob/master/task.py). Setuping when goal is met, how to step and what to return ( able to intercept values from environment ), separate goal from state, how to reset environment, and of course which environment to work with.

I temporarely put there also HER implementation / recalculation, but that could be done in more abstract way.

## What did not worked as expected
### Critics with different objective
Originally i intended to have one critic per subtask, in 3D navigation it means 3 separate critics, one per dimension. Follows by using attention layer for actor loss trough DDPG. However i was not able to make reasonable results with it, i guess mainly because it is highly desynchronized, but also i had less experience. This method was abandoned and replaced with MROCS approach.
### Good experience
Idea for LunarLander, environment of OpenAI gym, was to skip most of the steps from replaying. As those was mostly falling to the ground, while most important looks to me first steps when we start descending ( interesting angle from where we are dropped ) and last steps, when we starting to see in state landing ground. There i tried and failed.. well as my RL algo does not work at that environment even with standard reward and methodology, and recently i did not redo tests with my current framework. This feature is configurable via **good_reach** in BrainDescription (means state will appear in replay buffer draw only when during one episode in 1..goad_reach forward distance from that state appeared at least one good state, aka it make sense to learn from). If state is good or not you will define via task wrapper as one of returns of step function. Default setting is goad_reach=1, and good=[True]\*len(states), it means all states are good and can be used for replay learning.
### Curiosity PrioReplayBuff
Originally i wanted prioritize replay buffer experience based on how unexpected is state-action transition, but on the other side similiar thing is achieved via TD-error. As when td-error is almost 0, it means critic sucessfully predict outcome of actors(policy) actions and understand environment to that respect, and it is almost equal to my idea - how is unexpected state-action transition. Soo.. i just abandon this completly as reinventing wheel once again.
### Encoders double learning
Current [implementation](https://github.com/rezer0dai/rewheeler/blob/master/utils/ac.py) i allow to learn encoders ( RNN, or other encoder with gradients ) only trough critic learning, not actor one. I tried different combinations but others did not work well that time, but to be honest i did not have that time properly working framework / algorithm, so it deservers several more experiments.

### TODO
- run tests on more complex environments with fetch and deliver object as a starter
- td error as reward signal for curiosity driven tasks :
  Idea is basically that td error give us some idea how unexpected/novel was state (wrt environment+policy), we can use this as a signal and replace/add up to reward, though i think will be good to recalculate it overtime (so deduct from original reward original surprise signal and add current surprise). Well but this is just idea i recenly think little bit, did not have chance to do any hands on it yet.
- pararelism of replay buffer: floating n-step recalc, n-step GAE, reanalysing experience, RNN feature recalc. As now drawing and recalculating in replay buffer is done in sync with learning, however it can be done with multiple workers anytime considering certain constraints, thats why i dont see big problem in performance overhead with recalculating data in replay buffer as we can scale it.
- encoders learning, combinations critic/actor only/together
- good experience triage, likely on LunarLander environment
- RNN on raw inputs with pre-trained CNN
- Noisy Heads benchmark and evaluation of modifications effectivity
- GPU, currently i have access to only limited resources where GPU is not of those, but will do later on

## Reacher environment UnityML
Reacher environment episode is originally 1000 steps length (i cut it in 70 steps instead), have relatively complex reward function, and not exactly specified state-goal connection. Same time allows to run 20-'agents' same time.
  - first was essential to transform state :
```python
def transform(obs):
    return np.hstack([
        obs[3+4+3+3:3+4+3+3+3], #pendulumB position
        obs[:3+4+3+3], # pendulumA info
        obs[3+4+3+3+3:-4-3], # pundulumB rest of info
        obs[-1-3:] #speed + hand position
        ])
```
  - next was invested some engineering to get HER style reward which approximate goal of environment ( original reward function ) 
```python
def fun_reward(s, n, goal, her): # 3D navigation
    return (
            -.01 * (5 * CLOSE_ENOUGH < np.abs(s[0] - goal[0])),
            -.01 * (5 * CLOSE_ENOUGH < np.abs(s[1] - goal[1])),
            -.01 * (5 * CLOSE_ENOUGH < np.abs(s[2] - goal[2])),

            +.01 * (3 * CLOSE_ENOUGH > np.abs(s[0] - goal[0])),
            +.01 * (3 * CLOSE_ENOUGH > np.abs(s[1] - goal[1])),
            +.01 * (3 * CLOSE_ENOUGH > np.abs(s[2] - goal[2])),

            -.01 * (1 * CLOSE_ENOUGH > np.abs(s[0] - goal[0])),
            -.01 * (1 * CLOSE_ENOUGH > np.abs(s[1] - goal[1])),
            -.01 * (1 * CLOSE_ENOUGH > np.abs(s[2] - goal[2])),
            )
```
  hoho this looks almost like nothing like HER you say ? partially thats right, on the other side, HER approach i see as : 
    + resampling achievable goal from experience
    + 0/1 style reward

  In my case it is 9 rewards .1/-.1/.0, sparse enough, and easy to evaluate as it depends if we are {close enough / too close} to the goal.

## Jupyter notebooks
For checking my results / experiments you can follow rewheeler repo. In Particular :
  - [cross algo cooperation v1](https://github.com/rezer0dai/rewheeler/blob/master/COOP_v1.ipynb) ( periodically sync, both ways but different timing, of explorer networks )
  - [cross algo cooperation v2](https://github.com/rezer0dai/rewheeler/blob/master/COOP_v2.ipynb) ( periodically swap full actor networks ~ need to do more tests with PPO more on-policy fashion )
  - [DDPG](https://github.com/rezer0dai/rewheeler/blob/master/DDPG.ipynb) ( could be tunned better i believe, but needs more hypeparams tunning. And seems it learns really good my reward function, though it is slowest to learn the one of environment )
  - [PPO off](https://github.com/rezer0dai/rewheeler/blob/master/PPO.ipynb) ( pushed towards off-policy fashion, i need todo more tests on on-policy vs of-policy )
  - [PPO on](https://github.com/rezer0dai/rewheeler/blob/master/PPO_ON.ipynb) ( On-Policy ~ fast convergence )
  - [cross algo cooperation v2 - on+off smoothing](https://github.com/rezer0dai/rewheeler/blob/master/onoff_COOP_v2.ipynb) ( from on-policy PPO towards off, swaping DDPG + PPO networks )

For pre-trained weights let me know (twitter / github) i will share with you, but should be not a problem to train it by yourself. In anyway dont hesitate to ping me.
