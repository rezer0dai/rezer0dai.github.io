---
use_math: true
title: "GANs : utilization, loss, training, code and SimGAN"
tags:
  - gan
  - simgan
  - infogan
  - cyclegan
  - research
---

{% include toc %}

## Contribution
In this project I focused on [InfoGAN](https://arxiv.org/abs/1606.03657) and [CycleGAN](https://arxiv.org/abs/1703.10593) respectively. Mainly I utilized InfoGAN to train in CycleGAN fashion, therefore using only one generator - critic pair for transfer image from one to different domain, with possibility to easy extend this approach to more than two domains. On another front i experimented with novel (and maybe not so novel) loss function for training GAN (re)branding it SimGAN (Similiarity GAN). I also provide source code from my experiments where i implemented slightly different training schema, and easily extensible trough generator loss function via callback. Though code is is still experimental and in progress state. 

## Introduction
Two neural networks compete / cooperate to improve each other generative (generator) and classification (critic / discriminator) ability, in short : *"Generative Adversarial Networks"*. 
Starting perhaps chronologically pretty much the idea was described in this blog post on [cLSGAN](https://web.archive.org/web/20120312111546/http://yehar.com:80/blog/?p=167), and independently kicked off by this paper [GAN](https://arxiv.org/abs/1406.2661). While the second mentioned introduced z-noise vector and expand view on generator - discriminator as zero-sum game, provide implementation, results, underlying math and literally kicked of this field with huge potential of application. Other papers follow, from where i pickup selection, which i consider most influential ones for me :  
  - [LSGAN](https://arxiv.org/abs/1611.04076)
    - changed loss function to least squared error, which naturally remove need of sigmoid cross entropy one and stabilize learning process
  - [WGAN](https://arxiv.org/abs/1701.07875)
    - introduce different distribution distance metric to GANs
    - push more towards  [Adversarial sampling](https://pytorch.org/tutorials/beginner/fgsm_tutorial.html), as allows critic to be trained more thoroughly while preserving good gradient signal for generator
  - [RaGAN](https://arxiv.org/abs/1807.00734)
    - draw connection between GAN + WGAN from relativistic point of view, while same time able to use least square error in loss function
    - in addition here i can more intuitively to see cooperation vs competition, generated vs real samples, in loss function, where both appears to works well :
       - [GitHub](https://github.com/AlexiaJM/RelativisticGAN) of original author 
       - [GitHub](https://github.com/eriklindernoren/PyTorch-GAN/blob/master/implementations/relativistic_gan/relativistic_gan.py#L177) of most clean pytorch implementation of GANs I have seen so far
 
 ```python
err_g_pred = mse(y_pred - y_fake.mean(), torch.ones(1).expand_as(y_pred))

if cooperate: #cooperatitive setting
	err_g_fake = mse(y_fake - y_pred.mean(), -torch.ones(1).expand_as(y_fake))
else: #competition setting
	err_g_fake = mse(y_fake - y_pred.mean(), torch.zeros(1).expand_as(y_fake))

err_total = (err_g_real + err_g_fake) / 2.
```

Those papers were influential, for me, in a way, that it draws me back from viewing GANs as **zero-sum game**, to more of **cLSGAN + Adversarial sampling**.

## InfoGAN is all you need
There I moved to another nice paper called **Information Maximizing Generative Adversarial Nets (InfoGAN)**, which is breakthrough, at last for me, as it shows how to train classification, and generator as well, network in basically **unsupervised** manner via GANs. Details I encourage you to read in paper, but basic idea is to introduce labels to generator's input and critic's output and backprop it trough binary cross entropy. You can correct labels to correspond with our perception ( like in MNIST 10 labels, where you can force label 0 to relate to digit 0 ) via adding ground truth loss for labels, but in general case no need to do that, and critic will assign its own labeling (aka you can setup InfoGAN for MNIST dataset with 20, 10, or 4 labels and critic will handle it its own way, and will group images on its own labeling). 
{:refdef: style="text-align: center;"}
![MNIST 13 label Info-sim-GAN](https://rezer0dai.github.io/assets/images/mnist12_infog_13_a.png =300x)
![MNIST 13 label Info-sim-GAN](https://rezer0dai.github.io/assets/images/mnist12_infog_13_b.png =300x)
{: refdef}
As that was for me really nice research and impressive results, i continue to look for other interesting direction and capabilities of GANs. There i got trough **CycleGAN**, which showed me another possibilities  what can be done with GANs : utilize generator's loss function for specific purpose! And what they did for it was utilizing GAN framework to transfer image from one domain ( apples for example ) to another ( oranges ), as you can see :
{:refdef: style="text-align: center;"}
![CycleGAN](https://rezer0dai.github.io/assets/images/apple2orange_orig.png)
{: refdef}

How they did it :
  - introduced **cycle** loss for generator
  - compose more generators for the job
  - provide one domain picture as an input, and expect second domain picture as output ( no z-noise )
  
Pretty clean implementation you can find [here](https://github.com/eriklindernoren/PyTorch-GAN/blob/master/implementations/cyclegan/cyclegan.py).
Though at this point I was thinking, wow nice intercooperate more generators together and make it work is really impressive and show another possibilities for the future research. 

*But .. can be the same achieved via single **InfoGAN** where domain have just simple different labels ?* 

And **yes**, it can be achieved, simply by utilizing InfoGAN by this way :
 - provide labels which separates images to its domains
 - in one batch have approx. 1:1 ratio of images per domain
 
Basically only one essential thing you need to add to InfoGAN, update generator loss :
```python
def cycle_callback(
    gan, c, 
    real_data, label, 
    fake_data, fake_noise, fake_space, fake_label, 
    gan_loss):
    
    b_data = real_data.detach()
    b_label = fake_label.detach()
    a_data = fake_noise.detach().view(b_data.shape)
    a_label = torch.ones(b_label.shape).to(device) - b_label
    ab_data = fake_data.view(b_data.shape)

    id_b = gan.gc.gen(b_data, fake_space, b_label, c).view(b_data.shape)
    loss_identity = pixel_loss(id_b, b_data)

    cycle_data = gan.gc.gen(ab_data, fake_space, a_label, c).view(real_data.shape)
    loss_cycle = pixel_loss(cycle_data, a_data)
    
    return gan_loss + loss_identity * 5. + loss_cycle * 10.
```
Source code you can find [here](https://github.com/rezer0dai/info-cycle-sim-gan), which is basically my initial GAN framework I currently work with. For reference some output of training :
{:refdef: style="text-align: center;"}
![InfoGAN for domain transfer : apple2orange](https://rezer0dai.github.io/assets/images/apple2orange_infog.png)
{: refdef}

{:refdef: style="text-align: center;"}
![InfoGAN for domain transfer : horse2zebra](https://rezer0dai.github.io/assets/images/horse2zebra_infog.png)
{: refdef}
I admit horse2zebra are not too breath taking, and with implementation of original CycleGAN I get slightly better results on that front :
{:refdef: style="text-align: center;"}
![CycleGAN for domain transfer : horse2zebra](https://rezer0dai.github.io/assets/images/horse2zebra_orig.png)
{: refdef}
but it shows that InfoGAN can do the job, but need bit more work on hyperparameters and maybe way of training as well. As for example my approach have appareantelly problem with white horses. On the other side it opens up possibility to **transfer images trough many more domains**, than just 2, with single InfoGAN architecture and training! 

## SimGAN
To put it shortly as this is not backuped by any math from my side, just trough intuition and experiments. I come with use of another loss function, at first I implement it to **generator adversarial loss**, following intuition that we want generator to come up with similar output as original samples, while we actually dont care about zero-sum game, and as far as we get useful gradients from critic it is very OK for achieving our goal. Loss function used is pytorch *[CosineEmbeddingLoss](https://pytorch.org/docs/stable/nn.html?highlight=cosineembeddingloss#torch.nn.CosineEmbeddingLoss)* and output of critic is that one of [PatchGAN](https://arxiv.org/pdf/1611.07004.pdf) :
```python
def _eval_generator(self, c, real_data, fake_rollout):
    ''' we are expecting critic to have PatchGAN style output
    '''
    real_vals, _, _ = self.gc.eval(real_data, c)

    fake_noise, fake_space, fake_label = fake_rollout.roll()
    fake_data, (fake_vals, _, _) = self.gc(fake_noise, fake_space, fake_label)

    loss = []
    if self.adv_label_extended:
        for a, b in fake_rollout.label_cuts():
            idx = list(range(a, b))

            l_a = self.feature_matching_v2_loss(
                        fake_vals[idx].mean(0, keepdim=True),
                        real_vals[idx].detach(), 
                        torch.ones(len(idx)).to(fake_vals.device)
                        ).to(fake_vals.device)
            loss.append(l_a)

            l_b = self.feature_matching_v2_loss(
                        fake_vals[idx],
                        real_vals[idx].detach().mean(0, keepdim=True), 
                        torch.ones(len(idx)).to(fake_vals.device)
                        ).to(fake_vals.device)
            loss.append(l_b)            
        loss = [sum(loss) / len(loss)]
        
    l_ab = self.feature_matching_v2_loss(
                    fake_vals.mean(0, keepdim=True),
                    real_vals.detach().mean(0, keepdim=True), 
                    torch.ones(1).to(fake_vals.device)
                    ).to(fake_vals.device)
    loss.append(l_ab)
    return sum(loss) / len(loss), fake_data, real_vals
```
It also appears to work with combination of other gan losses for critic ( wgan, lsgan, ragan ), so in my code i opt in SimGAN loss for generator as default option. In this setup we seems no longer follow zero-sum game, as generator and critic follow their own objectives without direct competition. In addition with our objective of CycleGAN domain transfer, aka no z-noise vector, it looks less like GAN and more reassembly that idea of cLSGAN.

On the other hand, why not try this loss function also for critic : 
```python
def __call__(self, fake, real, label_cuts):
# if not provided lables we are good with label_cuts is one range covering whole batch
    loss = []
    for a, b in label_cuts:
        idx = list(range(a, b))
        l_a = nn.CosineEmbeddingLoss()(
                fake[idx], real[idx].mean(0, keepdim=True), 
                -torch.ones(fake[idx].shape[0]).to(fake.device))
                
        l_b = nn.CosineEmbeddingLoss()(
                real[idx], fake[idx].mean(0, keepdim=True), 
                -torch.ones(real[idx].shape[0]).to(fake.device))

        loss.append(l_a + l_b)
    return sum(loss) / len(loss)
```
And it appears to works, at least in scope of my limited tested environment tests ( MNIST, cyclegan : apple2orange, horse2zebra ). Actually above images from [InfoGAN is all you need](https://rezer0dai.github.io/info-cycle-sim-gan/#infogan-is-all-you-need) are generated via this cosine loss. But here we are back to generator and critic to follow inverse objectives. Here are some generated samples for MNIST dataset with this approach : 
{:refdef: style="text-align: center;"}
![horse from info-cycle-simgan](https://rezer0dai.github.io/assets/images/infog_horse.png =100x)
![MNIST with only 7 classes](https://rezer0dai.github.io/assets/images/infog_mnist7.png =100x)
![apple to orange info-cycle-simgan](https://rezer0dai.github.io/assets/images/infog_app2orange.png =100x)
{: refdef}
However, with this loss, one need to be careful to not let it saturate as it seems it easily happen. To avoid that batch should be composed of aproximatelly same ratio of images of different labels, and similarity should be measured in between same labels only. If labels are not available then mean over all sampes shoud do the job. To be noted, with my experiments i have [GP penalty](https://arxiv.org/abs/1704.00028), or rather its variant [DRAGAN](https://arxiv.org/abs/1705.07215), on by default..

## Artifacts in code and tries
 - at first I misunderstood exploration strategy for GANs, in fact I was thinking it have none.. and so I added option to have multiple generators with [Noisy Networks](https://arxiv.org/abs/1706.10295) heads as exploration method (check my [rewheeler project](https://rezer0dai.github.io/rewheeler)). On the other hand, later I realized that z-noise vector do exactly that job of exploration! Well at least in standard GAN, no actually in CycleGAN alike approaches where it is maybe worth to experiment with, so i left it implemented in my code
 - While training with z-noise vector, for me sounds interesting to train same z-noise batch with several different real batches. Where intuition follows, that during training i dont want to fit random noise to particular real batch distribution as i dont know if that is optimal match, but instead i want to train same noise with few different real batches, before i move to next random z-noise vector.  
 - as idea of training critic more often than generator sounds really interesting to me, i opt-in to framework. On the other side i allows critic to have smaller batches than generator for trainig but not the other way around, wich may be interesting to experiment with as well
 - follows from my rewheeler poject, i left code in framework to experiment with having multiple citics too
