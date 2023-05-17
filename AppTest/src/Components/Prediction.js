import logo_cool from '../assets/loading-79.gif'
import '../styles/Display.css';
import BarChart from './BarChart';



function Prediction({selectedModel,isDisplay,setIsDisplay,data}) {

  const datagenre = data[1]  
  
  const name = data[0]

  
  return isDisplay ? (
    <div className="Display">
      <div className='info'>
        <p>Modèle :  {selectedModel}</p>
        <p>
          MusIA a fini ces prédictions, voici le résultat :
        </p>
        <p>
          {name['title']} 
          <br></br>
          {name["artist"]}
        </p>
      </div>
         

      {name["image"] ?(
        <img className="Imagesong" alt="Album" src={name["image"]}></img>)
        :(
        <div></div>)
      }
      <div className='result'>
          <BarChart data={datagenre} />
      </div>
      

      
      
    </div>
  )  :  (
    <div className="Prediction">
        <img src={logo_cool} className="App-logo-gif" alt="gif" />
        <p>
          MusIA effectue ces predictions ! Veuillez patienter un instant. 
        </p>
        
    </div>
  );
} 

export default Prediction;
